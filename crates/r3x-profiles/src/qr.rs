use qrcode::QrCode;
use qrcode::render::svg;
use r3x_domain::R3xError;
use rqrr::PreparedImage;

pub fn encode_profile_qr_svg(content: &str) -> Result<String, R3xError> {
    if content.trim().is_empty() || content.len() > 4096 {
        return Err(R3xError::Validation(
            "QR content empty or exceeds 4096 bytes".to_owned(),
        ));
    }
    let code = QrCode::new(content.as_bytes())
        .map_err(|e| R3xError::Validation(format!("QR encoding failed: {e}")))?;
    Ok(code
        .render::<svg::Color<'_>>()
        .min_dimensions(256, 256)
        .dark_color(svg::Color("#1C1B1F"))
        .light_color(svg::Color("#FCF8FD"))
        .build())
}

pub fn decode_qr_image_bytes(image_bytes: &[u8]) -> Result<Vec<String>, R3xError> {
    let img = image::load_from_memory(image_bytes)
        .map_err(|e| R3xError::Validation(format!("invalid QR image: {e}")))?
        .to_luma8();

    let mut prepared = PreparedImage::prepare(img);
    let grids = prepared.detect_grids();
    let mut results = Vec::new();
    for grid in grids {
        if let Ok((_meta, content)) = grid.decode()
            && !content.is_empty()
        {
            results.push(content);
        }
    }
    if results.is_empty() {
        return Err(R3xError::Validation("no QR code found in image".to_owned()));
    }
    Ok(results)
}
