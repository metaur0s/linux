
#define BEEP_STATUS_SILENT   0
#define BEEP_STATUS_DISABLED 1

static uint beepStatus = 0;

static void beep_do (uint count) {

    unsigned long flags;

    raw_spin_lock_irqsave(&i8253_lock, flags);

    if (count) {
        count = PIT_TICK_RATE / count;
        /* set command for counter 2, 2 byte write */
        outb_p(0xB6, 0x43);
        /* select desired HZ */
        outb_p(count & 0xff, 0x42);
        outb((count >> 8) & 0xff, 0x42);
        /* enable counter 2 */
        outb_p(inb_p(0x61) | 3, 0x61);
    } else {
        /* disable counter 2 */
        outb(inb_p(0x61) & 0xFC, 0x61);
    }

    raw_spin_unlock_irqrestore(&i8253_lock, flags);
}

static ssize_t __cold_as_ice __optimize_size beep_write (struct file* file, const char __user* ubuf, size_t count, loff_t* ppos) {

    char buff[32];

    if (count == 0)
        return 0;

    if (count >= sizeof(buff))
        return -EFAULT;

    if(copy_from_user(buff,ubuf,count))
        return -EFAULT;

    buff[sizeof(buff) - 1] = 0;

    uint value = 0;

    if (sscanf(buff, "%u", &value) != 1)
        return -EFAULT;

    // O 1 DESATIVA
    if ((beepStatus = value) == 1)
        value = 0;

    beep_do(value);

    return count;
}

static struct proc_ops beepProcOps = {
    .proc_write = beep_write,
};
