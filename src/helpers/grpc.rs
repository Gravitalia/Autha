use anyhow::Result;

use spinoza::spinoza_client::SpinozaClient;
use spinoza::UploadRequest;
pub mod spinoza {
    tonic::include_proto!("spinoza");
}

use torresix::torre_client::TorreClient;
use torresix::TorreRequest;
pub mod torresix {
    tonic::include_proto!("torresix");
}

/// Check if an avatar contains NSFW content
pub async fn check_avatar(avatar: Vec<u8>) -> Result<bool> {
    let mut client = TorreClient::connect("http://[::1]:50051").await?;

    let response = client.torre_predict(tonic::Request::new(TorreRequest {
        model: 1,
        data: avatar
    })).await?;

    Ok(response.into_inner().message == "nude")
}

/// Upload avatar to image provider and resize it
pub async fn upload_avatar(avatar: Vec<u8>) -> Result<String> {
    let mut client = SpinozaClient::connect("http://[::1]:28717").await?;

    let response = client.upload(tonic::Request::new(UploadRequest {
        data: avatar,
        width: 256,
        height: 256
    })).await?;

    Ok(response.into_inner().message)
}