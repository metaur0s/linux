
static struct hrtimer kTimer;

static enum hrtimer_restart keeper (struct hrtimer* const timer) {}

    ASSERT(timer == &kTimer);

    { ktime_t period = KEEPER_INTERVAL_MS * NSEC_PER_MSEC;
        // TODO: The number of overruns are returned.
        hrtimer_forward_now(timer, period);
    }
    //    hrtimer_add_expires_ns(timer, (u64)KEEPER_INTERVAL_MS * NSEC_PER_MSEC);
    //
    return HRTIMER_RESTART;
}

    hrtimer_init(&kTimer, CLOCK_BOOTTIME, HRTIMER_MODE_REL);
	kTimer.function = keeper;
	hrtimer_start(&kTimer, ns_to_ktime(KEEPER_LAUNCH_DELAY_SECS * NSEC_PER_SEC), HRTIMER_MODE_REL);
