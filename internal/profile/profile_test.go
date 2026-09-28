package profile

import (
	"math"
	"testing"
	"time"
)

// at builds a time on day offset n (from a base) at the given local hour, in
// the profile's own zone so day/hour math lines up with the model's.
func at(p *Profile, base time.Time, days int, hour float64) time.Time {
	d := p.dayKey(base) + int64(days)
	return p.midnight(d).Add(time.Duration(hour * float64(time.Hour)))
}

func TestDeterministic(t *testing.T) {
	now := time.Date(2026, 9, 28, 15, 4, 5, 0, time.Local)
	a, b := New(42, now), New(42, now)
	if *a != *b {
		t.Fatalf("same seed produced different profiles:\n%+v\n%+v", a, b)
	}
	// every evaluation is a pure function of (seed, t)
	for i := 0; i < 500; i++ {
		tm := now.Add(time.Duration(i*37) * time.Minute)
		if a.Activity(tm) != b.Activity(tm) || a.ScreenOn(tm) != b.ScreenOn(tm) {
			t.Fatalf("Activity/ScreenOn diverged at %v", tm)
		}
		la, ca := a.Battery(tm)
		lb, cb := b.Battery(tm)
		if la != lb || ca != cb {
			t.Fatalf("Battery diverged at %v: (%d,%v) vs (%d,%v)", tm, la, ca, lb, cb)
		}
		if a.UptimeMillis(tm) != b.UptimeMillis(tm) {
			t.Fatalf("UptimeMillis diverged at %v", tm)
		}
	}
	// different seeds -> different personas (sample across seeds; a single
	// unlucky pair could match on one parameter, never on all)
	same := 0
	for seed := int64(1); seed <= 20; seed++ {
		if New(seed, now).Persona == New(seed+1000, now).Persona {
			same++
		}
	}
	if same > 0 {
		t.Fatalf("%d/20 seed pairs produced identical personas", same)
	}
}

func TestNewAnchors(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.Local)
	for seed := int64(1); seed <= 50; seed++ {
		p := New(seed, now)
		age := now.Sub(p.BornTime)
		if age < 30*24*time.Hour || age > 400*24*time.Hour {
			t.Errorf("seed %d: device age %v outside [30,400]d", seed, age)
		}
		up := now.Sub(p.BootTime)
		if up < 12*time.Hour || up > 20*24*time.Hour {
			t.Errorf("seed %d: boot age %v outside [0.5,20]d", seed, up)
		}
		if p.BootTime.Before(p.BornTime) {
			t.Errorf("seed %d: booted before activation", seed)
		}
	}
}

func TestClocksMonotonic(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.Local)
	p := New(7, now)
	prevSS, prevEl, prevUp := int64(math.MinInt64), time.Duration(math.MinInt64), time.Duration(math.MinInt64)
	for i := 0; i < 2000; i++ {
		tm := p.BootTime.Add(time.Duration(i) * time.Hour)
		if ss := p.SSTime(tm); ss <= prevSS {
			t.Fatalf("SSTime not strictly increasing at %v: %d after %d", tm, ss, prevSS)
		} else {
			prevSS = ss
		}
		if el := p.ElapsedRealtime(tm); el <= prevEl {
			t.Fatalf("ElapsedRealtime not increasing at %v", tm)
		} else {
			prevEl = el
		}
		up := p.UptimeMillis(tm)
		if up < prevUp {
			t.Fatalf("UptimeMillis went backwards at %v: %v after %v", tm, up, prevUp)
		}
		if up > p.ElapsedRealtime(tm) {
			t.Fatalf("uptime %v exceeds elapsed %v at %v", up, p.ElapsedRealtime(tm), tm)
		}
		prevUp = up
	}
	// uptime must lag elapsed by roughly the deep-sleep share
	el, up := p.ElapsedRealtime(now), p.UptimeMillis(now)
	lost := (el - up).Hours()
	if lost < el.Hours()*0.1 || lost > el.Hours()*0.45 {
		t.Errorf("deep-sleep share over boot: lost %.1fh of %.1fh elapsed (want ~10-45%%)", lost, el.Hours())
	}
}

func TestCircadianRhythm(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.Local)
	p := New(1234, now)
	base := p.BootTime
	var nightSum, eveningSum float64
	const days = 30
	for d := 0; d < days; d++ {
		nightSum += p.Activity(at(p, base, d, 3))
		eveningSum += p.Activity(at(p, base, d, 20.5))
	}
	night, evening := nightSum/days, eveningSum/days
	if night >= evening/5 {
		t.Errorf("3am activity %.3f not << 8pm activity %.3f", night, evening)
	}
	if evening < 0.3 {
		t.Errorf("evening peak too weak: %.3f", evening)
	}
}

func TestScreenOnRhythm(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.Local)
	p := New(99, now)
	var nightOn, dayOn, nightN, dayN int
	for d := 0; d < 14; d++ {
		for m := 0; m < 24*60; m += 10 {
			// sample three phases inside each 10-minute bucket: ScreenOn lights
			// the bucket's first prob*10 minutes, so bucket-start samples would
			// always read "on"
			for _, phase := range []time.Duration{1, 5, 9} {
				tm := at(p, p.BootTime, d, float64(m)/60).Add(phase * time.Minute)
				if h := p.hourOf(tm); h >= 1 && h < 6 {
					nightN++
					if p.ScreenOn(tm) {
						nightOn++
					}
				} else if h >= 10 && h < 22 {
					dayN++
					if p.ScreenOn(tm) {
						dayOn++
					}
				}
			}
		}
	}
	nr, dr := float64(nightOn)/float64(nightN), float64(dayOn)/float64(dayN)
	if nr >= dr/3 {
		t.Errorf("night screen-on ratio %.3f not far below day ratio %.3f", nr, dr)
	}
	if dr < 0.3 {
		t.Errorf("day screen-on ratio %.3f implausibly low", dr)
	}
}

func TestBatteryPhysics(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.Local)
	for _, seed := range []int64{5, 17, 88} {
		p := New(seed, now)
		sawCharge, sawDischarge := false, false
		prevLvl, prevCharging := -1, false
		// 10 days at 10-minute resolution
		for i := 0; i < 10*24*6; i++ {
			tm := p.BootTime.Add(time.Duration(i*10) * time.Minute)
			lvl, charging := p.Battery(tm)
			if lvl < 5 || lvl > 100 {
				t.Fatalf("seed %d: level %d outside [5,100] at %v", seed, lvl, tm)
			}
			if charging {
				sawCharge = true
				if prevCharging && lvl < prevLvl {
					t.Fatalf("seed %d: level dropped %d -> %d while charging at %v", seed, prevLvl, lvl, tm)
				}
			} else {
				sawDischarge = true
				// Not charging: level must not rise on its own. Two physically
				// legit exceptions between 10-minute samples: the previous
				// sample was charging (charger pulled mid-gap), or a plug-in
				// fast-filled (55%/h) straight to 100 within the gap.
				if prevLvl >= 0 && !prevCharging && lvl > prevLvl+1 && lvl != 100 {
					t.Fatalf("seed %d: level jumped %d -> %d while discharging at %v", seed, prevLvl, lvl, tm)
				}
			}
			prevLvl, prevCharging = lvl, charging
		}
		if !sawCharge || !sawDischarge {
			t.Errorf("seed %d: charge=%v discharge=%v, want both", seed, sawCharge, sawDischarge)
		}
		// across a long window the level must leave 100 (no "forever full")
		stuck := true
		for i := 0; i < 10*24*6; i++ {
			tm := p.BootTime.Add(time.Duration(i*10) * time.Minute)
			if lvl, _ := p.Battery(tm); lvl < 100 {
				stuck = false
				break
			}
		}
		if stuck {
			t.Errorf("seed %d: battery pinned at 100 for 10 days", seed)
		}
	}
}

func TestChargeHabitVaries(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.Local)
	// across personas and days both charge and no-charge nights must occur
	charged, skipped := 0, 0
	for seed := int64(1); seed <= 8; seed++ {
		p := New(seed, now)
		for d := int64(0); d < 60; d++ {
			if p.schedOf(d).chargeNight {
				charged++
			} else {
				skipped++
			}
		}
	}
	if charged == 0 || skipped == 0 {
		t.Fatalf("charge decisions lack variety: charged=%d skipped=%d", charged, skipped)
	}
}

func TestStateAggregate(t *testing.T) {
	now := time.Date(2026, 9, 28, 21, 0, 0, 0, time.Local)
	p := New(7, now)
	st := p.State(now)
	if st.Elapsed != now.Sub(p.BootTime) {
		t.Errorf("State.Elapsed = %v, want %v", st.Elapsed, now.Sub(p.BootTime))
	}
	if st.Uptime > st.Elapsed {
		t.Errorf("State.Uptime %v > Elapsed %v", st.Uptime, st.Elapsed)
	}
	lvl, ch := p.Battery(now)
	if st.BatteryLevel != lvl || st.Charging != ch {
		t.Errorf("State battery (%d,%v) != Battery (%d,%v)", st.BatteryLevel, st.Charging, lvl, ch)
	}
	if st.ScreenOn != p.ScreenOn(now) || st.Activity != p.Activity(now) {
		t.Errorf("State screen/activity inconsistent with direct evaluation")
	}
}
