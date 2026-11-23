#![no_main]

use kyriakon_mailparse::{
    boundary_param, headers, parse_address_list, split_message, walk_multipart,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_address_list(data);

    let Ok(message) = split_message(data) else {
        return;
    };
    let mut previous_end = 0;
    for header in headers(message.headers) {
        assert!(header.start() <= header.end(), "a span runs backwards");
        assert!(
            header.end() <= message.headers.len(),
            "a span leaves the block"
        );
        assert!(
            header.start() >= previous_end,
            "header spans overlap or run out of order"
        );
        previous_end = header.end();

        let value = header.value(message.headers);
        if header.is("from") || header.is("to") || header.is("cc") || header.is("reply-to") {
            let _ = parse_address_list(value);
        }
        if header.is("content-type") {
            if let Some(boundary) = boundary_param(value) {
                if let Ok(multipart) = walk_multipart(message.body, &boundary) {
                    for part in multipart.parts {
                        assert!(
                            part.headers.len() + part.separator.len() + part.body.len()
                                <= message.body.len()
                        );
                    }
                }
            }
        }
    }
});
