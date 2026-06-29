from usb_security import USBSecurityManager

if __name__ == "__main__":
    manager = USBSecurityManager("../data/intrusion_log.csv")
    manager.start()
    print("USB monitoring started from CLI. Press Ctrl+C to stop.")
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        manager.stop()
