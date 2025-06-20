// ignore_for_file: depend_on_referenced_packages

import 'dart:convert';
import 'dart:io';

import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';
import 'package:dio/dio.dart';
import 'package:logger/logger.dart';
import 'package:path/path.dart';
import 'package:path_provider/path_provider.dart';

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

  /// Returns the URL of the uploaded file and null if the upload fails.
  Future<String?> uploadFile({
    required File file,
    required String s3BucketName,
    required String s3Region,
    required String accessKey,
    required String secretKey,
    String? directory,
    int maxFileSizeMB = 100, // Add file size limit
  }) async {
    final String endpointUrl = 'https://$s3BucketName.s3.amazonaws.com';
    File? tempFile;

    try {
      // Check file size
      final fileSizeBytes = await file.length();
      final fileSizeMB = fileSizeBytes / (1024 * 1024);
      if (fileSizeMB > maxFileSizeMB) {
        libLogger.w('File too large: ${fileSizeMB.toStringAsFixed(2)}MB (max: ${maxFileSizeMB}MB)');
        return null;
      }

      // Check if file exists
      if (!await file.exists()) {
        libLogger.w('File does not exist: ${file.path}');
        return null;
      }

      final originalFilePath = file.path;
      final originalFileName = basename(originalFilePath);
      final sanitizedFileName = _sanitizeFileName(originalFileName);

      File fileToUpload = file;
      
      // Only create temp file if sanitization changed the name
      if (sanitizedFileName != originalFileName) {
        final tempDir = await getTemporaryDirectory();
        tempFile = File('${tempDir.path}/$sanitizedFileName');
        await tempFile.writeAsBytes(await file.readAsBytes());
        fileToUpload = tempFile;
        libLogger.i('Created temp file: ${tempFile.path}');
      }

      String fileName =
          "${directory == null ? "" : "$directory/"}${basename(fileToUpload.path)}";
      String method = 'PUT';
      String path = '/$fileName';
      final body = await fileToUpload.readAsBytes();

      Map<String, String> queryParams = {};

      // Calculate SHA-256 hash of the file contents
      String contentHash = sha256.convert(body).toString();
      String xAmzDate = _generateAmzDate();
      String dateStamp = _getDateStamp();

      // Determine content type based on file extension
      String contentType = _getContentType(extension(fileToUpload.path));

      // Headers (required for S3 request)
      Map<String, String> headers = {
        'Content-Type': contentType,
        'Host': '$s3BucketName.s3.amazonaws.com',
        'x-amz-content-sha256': contentHash,
        'x-amz-date': xAmzDate,
      };

      // Build the scope
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

      // Upload the file
      final uploadUrl = '$endpointUrl/$fileName';

      Response response = await dio.put(
        uploadUrl,
        data: body,
        options: Options(
          headers: headers,
          receiveTimeout: const Duration(minutes: 5), // Add timeout
          sendTimeout: const Duration(minutes: 5),
        ),
      );

      if (response.statusCode == 200) {
        libLogger.i('File uploaded successfully: $uploadUrl');
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
        libLogger.e('Upload error: $e');
      }
      return null;
    } finally {
      // Clean up temporary file
      if (tempFile != null && await tempFile.exists()) {
        try {
          await tempFile.delete();
          libLogger.d('Cleaned up temp file: ${tempFile.path}');
        } catch (e) {
          libLogger.w('Failed to delete temp file: $e');
        }
      }
    }
  }

  /// Get appropriate content type based on file extension
  String _getContentType(String fileExtension) {
    switch (fileExtension.toLowerCase()) {
      case '.jpg':
      case '.jpeg':
        return 'image/jpeg';
      case '.png':
        return 'image/png';
      case '.gif':
        return 'image/gif';
      case '.webp':
        return 'image/webp';
      case '.pdf':
        return 'application/pdf';
      case '.mp4':
        return 'video/mp4';
      case '.mov':
        return 'video/quicktime';
      case '.txt':
        return 'text/plain';
      default:
        return 'application/octet-stream';
    }
  }
}

/// Improved file name sanitization that preserves file extensions
String _sanitizeFileName(String fileName) {
  // Split filename and extension
  final nameWithoutExt = basenameWithoutExtension(fileName);
  final ext = extension(fileName);
  
  // Sanitize the name part only
  final sanitizedName = nameWithoutExt
      .replaceAll(RegExp(r'\s+'), '_') // Replace spaces with underscores
      .replaceAll(RegExp(r'[^\w\-_]'), '') // Remove special chars except hyphens and underscores
      .toLowerCase();
  
  // Ensure we don't have empty names
  final finalName = sanitizedName.isEmpty ? 'file' : sanitizedName;
  
  // Combine with original extension (in lowercase)
  return '$finalName${ext.toLowerCase()}';
}