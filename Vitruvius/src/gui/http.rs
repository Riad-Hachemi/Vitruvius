use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn get_html(theme: &str) -> &'static str {
    match theme {
        "gothic" => include_str!("../../gui/gothic.html"),
        _ => include_str!("../../gui/vitruvius_gui_2.0.html"),
    }
}

pub async fn serve(mut stream: TcpStream, ws_port: u16, theme: String) {
    let mut buf = [0u8; 512];
    let _ = stream.read(&mut buf).await;

    let html = get_html(&theme).replace("__WS_PORT__", &ws_port.to_string());

    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {len}\r\n\
         Cache-Control: no-cache\r\n\
         Connection: close\r\n\
         \r\n\
         {html}",
        len = html.len(),
    );

    let _ = stream.write_all(response.as_bytes()).await;
}
