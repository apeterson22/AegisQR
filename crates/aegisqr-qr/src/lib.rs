use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrTransportPlaceholder {
    pub animated_qr_placeholder: bool,
    pub spritesheet_placeholder: bool,
    pub pdf_contact_sheet_placeholder: bool,
}
