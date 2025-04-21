<!--
This README describes the package. If you publish this package to pub.dev,
this README's contents appear on the landing page for your package.

For information about how to write a good package README, see the guide for
[writing package pages](https://dart.dev/tools/pub/writing-package-pages).

For general information about developing packages, see the Dart guide for
[creating packages](https://dart.dev/guides/libraries/create-packages)
and the Flutter guide for
[developing packages and plugins](https://flutter.dev/to/develop-packages).
-->

A simple helper for uploading files to AWS S3. It returns the download URL if the upload is successful, OR null if it failed.

## Getting started

No special configuration required for this package.

## Usage

Get your AWS credentials: accessKey, secretKey, region, and S3 bucket name.

A typical usage example is shown below:

```dart

final result = await AwsS3Helper().uploadFile(
    file: fileToUpload,
    s3BucketName: "s3BucketName",
    s3Region: "s3Region",
    accessKey: "accessKey",
    secretKey: "secretKey",
    directory: "directory", //(Optional)
);

if (result != null) {
    loggger.f('File Uploaded successfully! URL: $result');
    return result;
} else {
    return null;
}
```

## Note

This simple package was created as existing package are either unstable or lacking maintenance. 
