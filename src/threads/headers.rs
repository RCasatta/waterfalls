use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::time::sleep;

use crate::{db::DBStore, fetch::Client, Error};

pub(crate) async fn headers_infallible(db: Arc<DBStore>, client: Client) {
    if let Err(e) = headers(db, client).await {
        log::error!("{:?}", e);
    }
}

pub async fn headers(db: Arc<DBStore>, client: Client) -> Result<(), Error> {
    let mut height = 0u32;
    let mut now = Instant::now();
    let mut last_height_print = height;
    loop {
        if now.elapsed() > Duration::from_secs(10) && height != last_height_print {
            now = Instant::now();
            last_height_print = height;
            println!("tip {}", height - 1);
        }
        match db.get_block_hash(height) {
            Ok(Some(_)) => {
                height += 1;
                continue;
            }
            Ok(None) => match client.block_hash(height).await {
                Ok(Some(block_hash)) => match db.set_block_hash(height, block_hash) {
                    Ok(_) => {
                        height += 1;
                        continue;
                    }
                    Err(e) => println!("A error: {e:?}"),
                },
                Ok(None) => (),
                Err(e) => println!("B error: {e:?}"),
            },
            Err(e) => println!("C error: {e:?}"),
        }

        sleep(std::time::Duration::from_secs(1)).await;
    }
}
