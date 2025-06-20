use hidapi::{HidApi, HidDevice};
use anyhow::{Context, Result};
const USAGE_PAGE_FIDO: u16 = 0xF1D0;
const REPORT_LEN: usize = 64;
const VENDOR_ID: u16 = 0x1209;
const PRODUCT_ID: u16 = 0xF1D0;
pub struct Device {
    dev: HidDevice,
}
impl Device {
    pub fn open() -> Result<Self> {
        let api = HidApi::new()?;
        for info in api.device_list() {
            if info.vendor_id() == VENDOR_ID && info.product_id() == PRODUCT_ID {
                let dev = info.open_device(&api)?;
                dev.set_blocking_mode(false)?;
                println!("[softpasskey] opened existing SoftPasskey HID device");
                return Ok(Self { dev });
            }
        }
        anyhow::bail!("SoftPasskey HID device not found. (Attach UsbDk virtual device first.)");
    }
    pub fn poll_recv(&self) -> Result<Option<[u8; REPORT_LEN]>> {
        let mut buf = [0u8; REPORT_LEN];
        match self.dev.read_timeout(&mut buf, 10) {
            Ok(0) => Ok(None),
            Ok(len) => {
                if len != REPORT_LEN {
                    println!("received short report {} bytes", len);
                }
                Ok(Some(buf))
            }
            Err(e) => Err(e.into()),
        }
    }
    pub fn send(&self, frame: &[u8; REPORT_LEN]) -> Result<()> {
        self.dev.write_all(frame).context("write HID")?;
        Ok(())
    }
}