// Package profile models a virtual Android device's "liveness": the dynamic
// signals risk-control SDKs cross-check to tell a real, lived-in phone from a
// fresh emulator — device age (ssTime) that never resets, boot/uptime clocks
// that advance monotonically, a day/night activity rhythm, and a battery curve
// that obeys physics (never forever-100%, charges overnight, occasionally
// forgotten).
//
// Every dynamic quantity is a PURE function of (Profile, time): there is no
// mutable state and no global RNG — all randomness comes from splitmix64-style
// hashes of (Seed, day/bucket, purpose-tag). Same seed + same time => identical
// behavior, which is what lets profiles ride along with emulator pooling and
// Snapshot/Restore without drifting.
package profile

import (
	"math"
	"time"
)

// Persona is the sampled "who lives here" parameter set: when this user wakes
// and sleeps, how strict their charging habit is, how much they use the phone.
type Persona struct {
	WakeHour, WakeStd   float64 // mean/stddev of wake-up time (hours, local)
	SleepHour, SleepStd float64 // mean/stddev of lights-out (hours; >24 = past midnight)
	WeekendDrift        float64 // weekend schedule shift (hours, later)
	NightOwl            bool    // ~15% of personas: everything shifts 2-3h later
	ChargeHabit         float64 // probability of plugging in overnight
	DailyActiveHours    float64 // rough screen-on budget per day
}

// Profile is one virtual device's behavioral identity.
type Profile struct {
	Seed     int64     // persona + daily-behavior sampling seed
	BornTime time.Time // first activation ("born"); the ssTime origin
	BootTime time.Time // current boot; the elapsedRealtime/monotonic origin
	Persona  Persona
}

// purpose tags for the hash-based RNG — every sampled quantity draws from its
// own tagged stream so adding a new draw never reshuffles existing ones.
const (
	tagWake = iota + 1
	tagWakeStd
	tagSleep
	tagSleepStd
	tagDrift
	tagOwl
	tagHabit
	tagActive
	tagAge
	tagBoot
	tagDayWake
	tagDaySleep
	tagAnomaly
	tagCharge
	tagGlance
	tagPlug
	tagTopStart
	tagTopAmt
)

// battery model constants (percent per hour unless noted).
const (
	battMin            = 5.0   // a real phone shuts down before 0
	battIdlePerHour    = 1.2   // awake, screen off
	battScreenPerHour  = 11.0  // extra at activity = 1 (full interactive use)
	battNightPerHour   = 0.5   // unplugged overnight (doze)
	battChargePerHour  = 55.0  // wall charging
	battLowStart       = 25.0  // wake up below this -> daytime top-up
	battNightHoldLevel = 100.0 // charged overnight holds here until wake
)

// New samples a persona from seed and anchors the device timeline at now:
// BornTime is a device age (30-400 days) in the past, BootTime a boot
// (0.5-20 days, never older than the device) in the past.
func New(seed int64, now time.Time) *Profile {
	ps := Persona{
		WakeHour:         clamp(7.5+0.8*gauss01(seed, tagWake), 5.5, 10),
		WakeStd:          0.5 + 0.5*uni01(seed, tagWakeStd),
		SleepHour:        23.5 + 1.0*gauss01(seed, tagSleep),
		SleepStd:         0.6 + 0.8*uni01(seed, tagSleepStd),
		WeekendDrift:     0.8 + 1.0*uni01(seed, tagDrift),
		NightOwl:         uni01(seed, tagOwl) < 0.15,
		ChargeHabit:      0.70 + 0.28*uni01(seed, tagHabit),
		DailyActiveHours: 3 + 4*uni01(seed, tagActive),
	}
	if ps.NightOwl {
		ps.WakeHour = clamp(ps.WakeHour+2.5, 7, 12)
		ps.SleepHour += 2.5 // drifts past midnight
	}
	// lights-out between 21:00 and 03:00
	ps.SleepHour = clamp(ps.SleepHour, 21, 27)

	ageDays := 30 + 370*uni01(seed, tagAge)
	bootDays := 0.5 + 19.5*uni01(seed, tagBoot)
	if bootDays > ageDays {
		bootDays = ageDays
	}
	return &Profile{
		Seed:     seed,
		BornTime: now.Add(-time.Duration(ageDays*24) * time.Hour),
		BootTime: now.Add(-time.Duration(bootDays*24) * time.Hour),
		Persona:  ps,
	}
}

// --- deterministic hash RNG ---

// hash64 is a splitmix64-style finalizer chained over the seed and tags.
func hash64(seed int64, tags ...uint64) uint64 {
	x := uint64(seed)
	for _, t := range tags {
		x += 0x9E3779B97F4A7C15 + t*0xBF58476D1CE4E5B9
		x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9
		x = (x ^ (x >> 27)) * 0x94D049BB133111EB
		x ^= x >> 31
	}
	return x
}

// uni01 samples U[0,1) deterministically from (seed, tags).
func uni01(seed int64, tags ...uint64) float64 {
	return float64(hash64(seed, tags...)>>11) * (1.0 / 9007199254740992.0) // 2^53
}

// gauss01 samples N(0,1) via Box-Muller over two tagged uniforms.
func gauss01(seed int64, tag uint64) float64 {
	u1 := uni01(seed, tag, 1)
	u2 := uni01(seed, tag, 2)
	if u1 < 1e-12 {
		u1 = 1e-12
	}
	return math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
}

func clamp(v, lo, hi float64) float64 { return math.Min(hi, math.Max(lo, v)) }

// --- calendar helpers (all in the device's local civil time, BornTime's zone) ---

func (p *Profile) offset() int64 {
	_, off := p.BornTime.Zone()
	return int64(off)
}

// dayKey numbers local calendar days since the unix epoch.
func (p *Profile) dayKey(t time.Time) int64 { return (t.Unix() + p.offset()) / 86400 }

// hourOf is the local time of day in hours [0,24).
func (p *Profile) hourOf(t time.Time) float64 {
	sec := (t.Unix() + p.offset()) % 86400
	if sec < 0 {
		sec += 86400
	}
	return float64(sec) / 3600
}

// midnight returns the instant of local midnight starting day d.
func (p *Profile) midnight(d int64) time.Time { return time.Unix(d*86400-p.offset(), 0) }

// --- daily schedule ---

// schedule is one realized day: actual wake/sleep hours plus that day's dice.
type schedule struct {
	wake, sleep float64 // hours since local midnight; sleep may exceed 24
	activityMul float64 // <1 on rare "barely touched the phone" days
	chargeNight bool    // plugged in when going to sleep this night
}

func (p *Profile) schedOf(d int64) schedule {
	wd := p.midnight(d).Weekday()
	ps := p.Persona
	wake := ps.WakeHour + ps.WakeStd*gauss01(p.Seed, uint64(d)^tagDayWake)
	sleep := ps.SleepHour + ps.SleepStd*gauss01(p.Seed, uint64(d)^tagDaySleep)
	if wd == time.Saturday || wd == time.Sunday {
		wake += ps.WeekendDrift
		sleep += ps.WeekendDrift
	}
	mul := 1.0
	switch r := uni01(p.Seed, uint64(d), tagAnomaly); {
	case r < 0.03: // ~3% of days: stayed up late
		sleep += 3
	case r < 0.05: // ~2% of days: phone mostly untouched
		mul = 0.15
	}
	wake = clamp(wake, 4.5, 13)
	sleep = clamp(sleep, wake+3, 30)
	return schedule{
		wake:        wake,
		sleep:       sleep,
		activityMul: mul,
		chargeNight: uni01(p.Seed, uint64(d), tagCharge) < ps.ChargeHabit,
	}
}

// peaks are the daily usage rhythm: morning check, lunch, heavy evening block,
// anchored to the realized wake/sleep so the shape follows the person.
func (s schedule) peaks() [3]peak {
	return [3]peak{
		{s.wake + 1.2, 0.9, 0.5},
		{(s.wake + s.sleep) / 2, 1.3, 0.6},
		{s.sleep - 2.0, 1.6, 1.0},
	}
}

type peak struct{ mu, sigma, amp float64 }

func gaussPeak(x, mu, sigma float64) float64 {
	z := (x - mu) / sigma
	return math.Exp(-0.5 * z * z)
}

const dayFloor = 0.08 // background usage while awake (notifications, glances)

func (s schedule) dayActivity(h float64) float64 {
	a := dayFloor
	for _, pk := range s.peaks() {
		a += pk.amp * gaussPeak(h, pk.mu, pk.sigma)
	}
	return clamp(a*s.activityMul, 0, 1)
}

// activityIntegral is ∫activity dh over hours [a,b] of the awake window — the
// analytic solution (gaussian CDF) that lets the battery model integrate a
// whole day in O(1) instead of sampling.
func (s schedule) activityIntegral(a, b float64) float64 {
	phi := func(x float64) float64 { return 0.5 * (1 + math.Erf(x/math.Sqrt2)) }
	sum := dayFloor * (b - a)
	for _, pk := range s.peaks() {
		sum += pk.amp * pk.sigma * math.Sqrt(2*math.Pi) *
			(phi((b-pk.mu)/pk.sigma) - phi((a-pk.mu)/pk.sigma))
	}
	return sum * s.activityMul
}

// --- exported evaluations: all pure functions of (p, t) ---

// ElapsedRealtime is ms-of-Android's clock: time since boot, deep sleep
// included (CLOCK_BOOTTIME semantics).
func (p *Profile) ElapsedRealtime(t time.Time) time.Duration { return t.Sub(p.BootTime) }

// SSTime is the device age in seconds (born = first activation): continuously
// increasing, survives reboots — the value server-side risk models sanity-check
// against account age.
func (p *Profile) SSTime(t time.Time) int64 { return int64(t.Sub(p.BornTime).Seconds()) }

// UptimeMillis is time since boot MINUS accumulated deep sleep (Android's
// SystemClock.uptimeMillis semantics). Deep sleep is approximated as 85% of
// each night's screen-off window (real devices doze, not fully suspend).
func (p *Profile) UptimeMillis(t time.Time) time.Duration {
	elapsed := p.ElapsedRealtime(t)
	if elapsed <= 0 {
		return 0
	}
	deep := 0.0 // hours
	d0, d1 := p.dayKey(p.BootTime), p.dayKey(t)
	for d := d0; d <= d1; d++ {
		s, sNext := p.schedOf(d), p.schedOf(d+1)
		start := p.midnight(d).Add(time.Duration(s.sleep * float64(time.Hour)))
		end := p.midnight(d + 1).Add(time.Duration(sNext.wake * float64(time.Hour)))
		if start.Before(p.BootTime) {
			start = p.BootTime
		}
		if end.After(t) {
			end = t
		}
		if end.After(start) {
			deep += end.Sub(start).Hours()
		}
	}
	return elapsed - time.Duration(deep*0.85*float64(time.Hour))
}

// Activity returns interaction intensity in [0,1]: a sum of usage peaks inside
// the awake window, ~0 overnight with rare "check the phone at 3am" blips.
func (p *Profile) Activity(t time.Time) float64 {
	d, h := p.dayKey(t), p.hourOf(t)
	s := p.schedOf(d)
	if h >= s.wake && h < s.sleep {
		return s.dayActivity(h)
	}
	// early morning may still belong to yesterday's late night
	if h < s.wake {
		if ys := p.schedOf(d - 1); h+24 >= ys.wake && h+24 < ys.sleep {
			return ys.dayActivity(h + 24)
		}
	}
	// asleep: near-zero, with a low-probability "glance" per 10-minute bucket
	if uni01(p.Seed, uint64(d), uint64(t.Unix()/600), tagGlance) < 0.015 {
		return 0.45
	}
	return 0.02
}

// ScreenOn quantizes Activity into a deterministic on/off sequence: each
// 10-minute bucket is lit for its first prob*10 minutes, where prob =
// clamp(Activity*1.3). Same t always yields the same answer (no state).
func (p *Profile) ScreenOn(t time.Time) bool {
	prob := clamp(p.Activity(t)*1.3, 0, 1)
	frac := float64(t.Unix()%600) / 600
	return frac < prob
}

// discharge is the battery % burned over hours [a,b] of the awake window:
// idle background plus screen-on cost scaled by the activity integral.
func (p *Profile) discharge(s schedule, a, b float64) float64 {
	a, b = math.Max(a, s.wake), math.Min(b, s.sleep)
	if b <= a {
		return 0
	}
	return (b-a)*battIdlePerHour + battScreenPerHour*s.activityIntegral(a, b)
}

// topUp models the daytime charge that happens when a night was skipped:
// starts 0.5-2.5h after waking, adds a deterministic amount.
func (p *Profile) topUp(d int64, s schedule, wakeLvl float64) (start, end, rate float64, ok bool) {
	if wakeLvl >= battLowStart {
		return 0, 0, 0, false
	}
	amount := math.Min(100-wakeLvl, 55+25*uni01(p.Seed, uint64(d), tagTopAmt))
	start = s.wake + 0.5 + 2*uni01(p.Seed, uint64(d), tagTopStart)
	end = math.Min(start+amount/battChargePerHour, s.sleep)
	return start, end, battChargePerHour, true
}

// awakeAt evaluates the battery curve at hour h inside the awake window,
// given the level at wake. Discharge and any top-up compose so that level is
// monotonic non-increasing while discharging and strictly rising while charging.
func (p *Profile) awakeAt(d int64, s schedule, wakeLvl, h float64) (float64, bool) {
	lvl := wakeLvl - p.discharge(s, s.wake, h)
	charging := false
	if st, en, rate, ok := p.topUp(d, s, wakeLvl); ok {
		if h > st {
			lvl += rate * (math.Min(h, en) - st)
		}
		if h >= st && h < en && lvl < 100 {
			charging = true
		}
	}
	return clamp(lvl, battMin, 100), charging
}

// nightAt evaluates the night that begins at sleep of day d, at hour hh
// (hours since midnight of day d, so >24 means the next morning). A charged
// night fills linearly to 100 and holds (charging=false at 100 => "Full");
// an uncharged night trickle-drains.
func (p *Profile) nightAt(d int64, s schedule, sleepLvl, hh float64) (float64, bool) {
	if hh <= s.sleep {
		return clamp(sleepLvl, battMin, 100), false
	}
	if !s.chargeNight {
		return clamp(sleepLvl-(hh-s.sleep)*battNightPerHour, battMin, 100), false
	}
	plug := s.sleep + 0.5*uni01(p.Seed, uint64(d), tagPlug) // plug in within ~30min
	if hh < plug {
		return clamp(sleepLvl-(hh-s.sleep)*battNightPerHour, battMin, 100), false
	}
	lvl := sleepLvl + (hh-plug)*battChargePerHour
	if lvl >= battNightHoldLevel {
		return battNightHoldLevel, false
	}
	return lvl, true
}

// sleepLevel is the battery level at lights-out of day d given the wake level.
func (p *Profile) sleepLevel(d int64, s schedule, wakeLvl float64) float64 {
	lvl := wakeLvl - p.discharge(s, s.wake, s.sleep)
	if st, en, rate, ok := p.topUp(d, s, wakeLvl); ok {
		lvl += rate * (en - st)
	}
	return clamp(lvl, battMin, 100)
}

// Battery returns the charge level (percent, always in [5,100]) and whether
// the charger is attached at t. Computed analytically by walking the day
// recurrence from BornTime — O(device age in days), no hidden state, so the
// curve is continuous across day boundaries and identical on every call.
func (p *Profile) Battery(t time.Time) (level int, charging bool) {
	d, h := p.dayKey(t), p.hourOf(t)
	d0 := p.dayKey(p.BornTime)
	if d < d0 {
		return 100, false // before activation: fresh, full
	}
	wakeLvl := 100.0 // devices ship charged
	var prevS schedule
	prevSleepLvl := 0.0
	for day := d0; day < d; day++ {
		s := p.schedOf(day)
		e := p.sleepLevel(day, s, wakeLvl)
		prevS, prevSleepLvl = s, e
		wakeLvl, _ = p.nightAt(day, s, e, 24+p.schedOf(day+1).wake)
	}
	s := p.schedOf(d)
	var lvl float64
	switch {
	case h >= s.wake && h < s.sleep:
		lvl, charging = p.awakeAt(d, s, wakeLvl, h)
	case h < s.wake && d == d0:
		lvl, charging = 100, false // activation morning
	case h < s.wake:
		lvl, charging = p.nightAt(d-1, prevS, prevSleepLvl, 24+h)
	default: // evening, after lights-out
		lvl, charging = p.nightAt(d, s, p.sleepLevel(d, s, wakeLvl), h)
	}
	return int(math.Round(clamp(lvl, battMin, 100))), charging
}

// State is the one-call snapshot of everything a guest might read.
type State struct {
	ScreenOn     bool
	BatteryLevel int
	Charging     bool
	Activity     float64
	Elapsed      time.Duration // since boot (includes deep sleep)
	Uptime       time.Duration // since boot (excludes deep sleep)
}

// State aggregates the liveness signals at t.
func (p *Profile) State(t time.Time) State {
	lvl, ch := p.Battery(t)
	return State{
		ScreenOn:     p.ScreenOn(t),
		BatteryLevel: lvl,
		Charging:     ch,
		Activity:     p.Activity(t),
		Elapsed:      p.ElapsedRealtime(t),
		Uptime:       p.UptimeMillis(t),
	}
}
