// ignore_for_file: depend_on_referenced_packages

import 'dart:convert';
import 'dart:io';

import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';
import 'package:dio/dio.dart';
import 'package:logger/logger.dart';
import 'package:path/path.dart';

var libLogger = Logger();

class AwsS3Helper {
  Dio dio = Dio();

  // AWS Signature V4 signing process
  String _getCanonicalHeaders(Map<String, String> headers) {
    List<String> canonicalHeaders =
        headers.entries
            .map((entry) => '${entry.key.toLowerCase()}:${entry.value.trim()}')
            .toList()
          ..sort();
    return '${canonicalHeaders.join('\n')}\n';
  }

  String _getSignedHeaders(Map<String, String> headers) {
    List<String> headerKeys =
        headers.keys.map((key) => key.toLowerCase()).toList()..sort();
    return headerKeys.join(';');
  }

  String _getCanonicalRequest(
    String method,
    String path,
    Map<String, String> queryParams,
    Map<String, String> headers,
    List<int> body,
  ) {
    String canonicalHeaders = _getCanonicalHeaders(headers);
    String signedHeaders = _getSignedHeaders(headers);

    String queryString = queryParams.entries
        .map((entry) => '${entry.key}=${entry.value}')
        .join('&');

    return '$method\n$path\n$queryString\n$canonicalHeaders\n$signedHeaders\n${_hashBody(body)}';
  }

  String _hashBody(List<int> body) {
    return body.isEmpty ? '' : sha256.convert(body).toString();
  }

  String _hashString(String data) {
    return sha256.convert(utf8.encode(data)).toString();
  }

  String _getStringToSign(
    String canonicalRequest,
    String xAmzDate,
    String scope,
  ) {
    String canonicalRequestHash = _hashString(canonicalRequest);
    return 'AWS4-HMAC-SHA256\n$xAmzDate\n$scope\n$canonicalRequestHash';
  }

  String _signRequest(
    String stringToSign,
    String scope,
    String secretKey,
    String region,
  ) {
    String dateStamp = _getDateStamp();
    List<int> kSecret = utf8.encode('AWS4$secretKey');
    List<int> kDate = _hmacSha256(kSecret, utf8.encode(dateStamp));
    List<int> kRegion = _hmacSha256(kDate, utf8.encode(region));
    List<int> kService = _hmacSha256(kRegion, utf8.encode('s3'));
    List<int> kSigning = _hmacSha256(kService, utf8.encode('aws4_request'));
    return hex.encode(_hmacSha256(kSigning, utf8.encode(stringToSign)));
  }

  List<int> _hmacSha256(List<int> key, List<int> data) {
    var hmac = Hmac(sha256, key);
    return hmac.convert(data).bytes;
  }

  // Generate the x-amz-date (timestamp in UTC)
  String _generateAmzDate() {
    DateTime now = DateTime.now().toUtc();
    return "${now.year.toString().padLeft(4, '0')}${(now.month).toString().padLeft(2, '0')}${(now.day).toString().padLeft(2, '0')}T${(now.hour).toString().padLeft(2, '0')}${(now.minute).toString().padLeft(2, '0')}${(now.second).toString().padLeft(2, '0')}Z";
  }

  // Add this method to get just the date portion
  String _getDateStamp() {
    DateTime now = DateTime.now().toUtc();
    return "${now.year.toString().padLeft(4, '0')}${(now.month).toString().padLeft(2, '0')}${(now.day).toString().padLeft(2, '0')}";
  }

  Future<String?> uploadFileToS3({
    required File file,
    required String s3BucketName,
    required String s3Region,
    required String accessKey,
    required String secretKey,
    String? directory,
  }) async {
    final String endpointUrl = 'https://$s3BucketName.s3.amazonaws.com';

    try {
      String fileName =
          "${directory == null ? "" : "$directory/"}${basename(file.path)}";
      String method = 'PUT';
      String path = '/$fileName';
      final body = await file.readAsBytes();

      Map<String, String> queryParams = {};

      // Calculate SHA-256 hash of the file contents (as per AWS requirements)
      String contentHash = sha256.convert(body).toString();
      String xAmzDate = _generateAmzDate();
      String dateStamp = _getDateStamp();

      // Headers (required for S3 request)
      Map<String, String> headers = {
        'Content-Type': 'application/octet-stream',
        'Host': '$s3BucketName.s3.amazonaws.com',
        'x-amz-content-sha256': contentHash,
        'x-amz-date': xAmzDate,
      };

      // Build the scope (date/region/s3/aws4_request)
      String scope = '$dateStamp/$s3Region/s3/aws4_request';

      // Canonical Request
      String canonicalRequest = _getCanonicalRequest(
        method,
        path,
        queryParams,
        headers,
        body,
      );

      // Creating the String to Sign
      String stringToSign = _getStringToSign(canonicalRequest, xAmzDate, scope);

      // Signing the request
      String signedRequest = _signRequest(
        stringToSign,
        scope,
        secretKey,
        s3Region,
      );

      // Headers with the Authorization field
      String signedHeaders = _getSignedHeaders(headers);
      headers['Authorization'] =
          'AWS4-HMAC-SHA256 '
          'Credential=$accessKey/$scope, '
          'SignedHeaders=$signedHeaders, '
          'Signature=$signedRequest';

      // Sending the request with the signed headers
      final uploadUrl = '$endpointUrl/$fileName';
      libLogger.f('UploadedUrl: $uploadUrl');

      Response response = await dio.put(
        uploadUrl,
        data: body,
        options: Options(headers: headers),
      );
      libLogger.w('response: ${response.toString()}');

      if (response.statusCode == 200) {
        libLogger.f('File uploaded successfully');
        return uploadUrl;
      } else {
        libLogger.w('File upload failed: ${response.statusCode}');
        return null;
      }
    } catch (e) {
      if (e is DioException) {
        libLogger.e(
          'Dio error: ${e.response?.statusCode} - ${e.response?.data}',
        );
      } else {
        libLogger.e('Unknown error: $e');
      }
      return null;
    }
  }
}
