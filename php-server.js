// === CONFIGURABLE VARIABLES ===
const HOSTNAME = '0.0.0.0';
const HTTPS_PORT = 443;
const HTTP_PORT = 80;

const WEB_ROOT_DIR = './public'; // Enter a relative or absolute path
const SSL_CERT_PATH = './certs/cert.pem';
const SSL_KEY_PATH = './certs/key.pem';

const PHP_SOCKET_PATH = '/run/php/php7.4-fpm.sock'; // Adjust based on your PHP-FPM socket path
const PHP_USE_DEFAULT = true; // Direct requests for non-existent files to index.php in the web root
const PHP_TIMEOUT_MS = 5000; // Set to 0 to disable

const ENABLE_HTTPS = false;
const ENABLE_HTTP2 = true;
const REDIRECT_HTTP_TO_HTTPS = false;
const ENABLE_HTTP = true;
const ENABLE_BROTLI = true;
const ENABLE_GZIP = true;
const ENABLE_CORS = false;
const ENABLE_CACHE_CONTROL = true;
const CACHE_MAX_AGE_SECONDS = 3600;
const ENABLE_ETAG = true;
// ==============================

const fs = require('fs');
const path = require('path');
const url = require('url');

const mimeTypes = {
  '.avi': 'video/x-msvideo',
  '.br': 'application/brotli',
  '.bz2': 'application/x-bzip2',
  '.css': 'text/css',
  '.csv': 'text/csv',
  '.doc': 'application/msword',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.eot': 'application/vnd.ms-fontobject',
  '.flv': 'video/x-flv',
  '.gif': 'image/gif',
  '.gz': 'application/gzip',
  '.htm': 'text/html',
  '.html': 'text/html',
  '.ico': 'image/x-icon',
  '.jpeg': 'image/jpeg',
  '.jpg': 'image/jpeg',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.mkv': 'video/x-matroska',
  '.mov': 'video/quicktime',
  '.mp3': 'audio/mpeg',
  '.mp4': 'video/mp4',
  '.ogg': 'audio/ogg',
  '.otf': 'application/font-otf',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.tar': 'application/x-tar',
  '.tar.bz2': 'application/x-bzip2',
  '.tar.gz': 'application/gzip',
  '.tgz': 'application/gzip',
  '.ttf': 'application/font-ttf',
  '.txt': 'text/plain',
  '.wav': 'audio/wav',
  '.webm': 'video/webm',
  '.wmv': 'video/x-ms-wmv',
  '.woff': 'application/font-woff',
  '.xls': 'application/vnd.ms-excel',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.xml': 'application/xml',
  '.zip': 'application/zip'
};

function logRequest(req, statusCode, details = '') {
  const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
  console.log(`[${now}] ${req.method} ${req.url} -> ${statusCode}${details ? ' - ' + details : ''}`);
}

function generateETag(buffer) {
  const crypto = require('crypto');
  return crypto.createHash('md5').update(buffer).digest('hex');
}

function handlePHPRequest(req, res, filePath, webRoot) {
  const { spawn } = require('child_process');
  const parsedUrl = url.parse(req.url);
  const env = {
    SCRIPT_FILENAME: filePath,
    SCRIPT_NAME: parsedUrl.pathname,
    REQUEST_METHOD: req.method,
    QUERY_STRING: parsedUrl.query || '',
    CONTENT_TYPE: req.headers['content-type'] || '',
    CONTENT_LENGTH: req.headers['content-length'] || '',
    REQUEST_URI: req.url,
    DOCUMENT_ROOT: webRoot,
    GATEWAY_INTERFACE: 'CGI/1.1',
    SERVER_PROTOCOL: 'HTTP/1.1',
    REMOTE_ADDR: req.socket.remoteAddress || '',
    SERVER_NAME: HOSTNAME
  };

  const php = spawn('cgi-fcgi', ['-bind', '-connect', PHP_SOCKET_PATH], { env });

  let timeout = null;
  if (PHP_TIMEOUT_MS) {
    timeout = setTimeout(() => {
      php.kill();
      res.writeHead(504);
      res.end('PHP script timed out');
      logRequest(req, 504, 'PHP timeout');
    }, PHP_TIMEOUT_MS);
  }

  let headersSent = false;
  let statusCode = 200;
  let buffer = '';

  php.stdout.on('data', (data) => {
    const str = data.toString();
    buffer += str;

    if (!headersSent) {
      const headerEnd = buffer.indexOf("\r\n\r\n");
      if (headerEnd !== -1) {
        const headerStr = buffer.slice(0, headerEnd);
        const headers = headerStr.split("\r\n");
        for (const line of headers) {
          const [key, ...rest] = line.split(': ');
          const value = rest.join(': ');
          if (key.toLowerCase() === 'status') {
            statusCode = parseInt(value);
          } else {
            res.setHeader(key, value);
          }
        }
        res.writeHead(statusCode);
        res.write(buffer.slice(headerEnd + 4));
        headersSent = true;
      }
    } else {
      res.write(data);
    }
  });

  php.stderr.on('data', (data) => {
    console.error('PHP-FPM error:', data.toString());
  });

  php.on('close', (code) => {
	if (code == 4) return; // Process was terminated
    if (PHP_TIMEOUT_MS) clearTimeout(timeout);
    if (!headersSent) {
      res.writeHead(502);
      res.end('No output from PHP script');
      logRequest(req, 502, 'No PHP output');
    } else {
      res.end();
      logRequest(req, statusCode, 'PHP request');
    }
  });

  req.pipe(php.stdin);
}

function handleRequest(req, res) {
  if (ENABLE_CORS) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Origin, Range, Content-Type, Accept, Authorization');
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
	  logRequest(req, 204, 'CORS preflight');
      return;
    }
  }

  const parsedUrl = url.parse(req.url);
  const pathname = decodeURIComponent(parsedUrl.pathname);

  if (pathname.includes('\0')) {
    res.writeHead(400);
    res.end('Bad request');
	logRequest(req, 400, 'Null byte in URL');
    return;
  }

  const webRoot = path.resolve(__dirname, WEB_ROOT_DIR);
  const safePath = path.normalize(path.join(webRoot, pathname));
  const indexPath = path.normalize(path.join(webRoot, 'index.php'));

  if (!safePath.startsWith(webRoot)) {
    res.writeHead(403);
    res.end('Access denied');
	logRequest(req, 403, 'Path traversal attempt');
    return;
  }

  if (path.basename(safePath).startsWith('.')) {
    res.writeHead(403);
    res.end('Access denied');
	logRequest(req, 403, 'Attempt to access hidden file');
    return;
  }

  let filePath = safePath;

  if (fs.existsSync(filePath) && fs.statSync(filePath).isDirectory()) {
    const indexHtml = path.join(filePath, 'index.html');
    const indexHtm = path.join(filePath, 'index.htm');
	const indexPhp = path.join(filePath, 'index.php');
    if (fs.existsSync(indexHtml)) filePath = indexHtml;
    else if (fs.existsSync(indexHtm)) filePath = indexHtm;
	else if (fs.existsSync(indexPhp)) filePath = indexPhp;
    else {
      res.writeHead(403);
      res.end('Directory listing not allowed');
	  logRequest(req, 403, 'No index file in directory');
      return;
    }
  }

  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.php') {
    handlePHPRequest(req, res, filePath, webRoot);
    return;
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
	  if (PHP_USE_DEFAULT) {
        handlePHPRequest(req, res, indexPath, webRoot);
        return;
	  } else {
        res.writeHead(404);
        res.end('File not found');
	    logRequest(req, 404);
        return;
	  }
    }

    const mimeType = mimeTypes[ext] || 'application/octet-stream';
    const headers = {
      'Content-Type': mimeType,
    };

    if (ENABLE_CACHE_CONTROL) {
      headers['Cache-Control'] = `public, max-age=${CACHE_MAX_AGE_SECONDS}`;
    }

    if (ENABLE_ETAG) {
      const etag = generateETag(fs.readFileSync(filePath));
      if (req.headers['if-none-match'] === etag) {
        res.writeHead(304);
        res.end();
		logRequest(req, 304, 'ETag match');
        return;
      }
      headers['ETag'] = etag;
    }

    const range = req.headers.range;
    const totalSize = stats.size;

    if (range) {
      const match = range.match(/bytes=(\d*)-(\d*)/);
      if (!match) {
        res.writeHead(416, { 'Content-Range': `bytes */${totalSize}` });
        res.end();
		logRequest(req, 416, 'Invalid range');
        return;
      }

      const start = match[1] === '' ? 0 : parseInt(match[1], 10);
      const end = match[2] === '' ? totalSize - 1 : parseInt(match[2], 10);

      if (isNaN(start) || isNaN(end) || start > end || end >= totalSize) {
        res.writeHead(416, { 'Content-Range': `bytes */${totalSize}` });
        res.end();
		logRequest(req, 416, 'Invalid range values');
        return;
      }

      const chunkSize = end - start + 1;
      headers['Content-Range'] = `bytes ${start}-${end}/${totalSize}`;
      headers['Accept-Ranges'] = 'bytes';
      headers['Content-Length'] = chunkSize;
      res.writeHead(206, headers);
      fs.createReadStream(filePath, { start, end }).pipe(res);
	  logRequest(req, 206, `Range: ${start}-${end}`);
      return;
    }

    const acceptEncoding = req.headers['accept-encoding'] || '';
    const stream = fs.createReadStream(filePath);
    const compressedExts = ['.gz', '.tgz', '.zip', '.bz2', '.br', '.tar.bz2', '.tar.gz'];

    if (!compressedExts.includes(ext)) {
	  const zlib = require('zlib');
      if (ENABLE_BROTLI && acceptEncoding.includes('br')) {
        headers['Content-Encoding'] = 'br';
        res.writeHead(200, headers);
        stream.pipe(zlib.createBrotliCompress()).pipe(res);
		logRequest(req, 200, 'Brotli');
        return;
      } else if (ENABLE_GZIP && acceptEncoding.includes('gzip')) {
        headers['Content-Encoding'] = 'gzip';
        res.writeHead(200, headers);
        stream.pipe(zlib.createGzip()).pipe(res);
		logRequest(req, 200, 'Gzip');
        return;
      }
    }

    headers['Content-Length'] = totalSize;
    res.writeHead(200, headers);
    stream.pipe(res);
	logRequest(req, 200);
  });
}

if (!ENABLE_HTTPS && !ENABLE_HTTP && !REDIRECT_HTTP_TO_HTTPS) {
  console.error('At least one type of server must be enabled.');
  process.exit(1);
}

if (ENABLE_HTTPS) {
  try {
    let sslOptions = {
      key: fs.readFileSync(SSL_KEY_PATH),
      cert: fs.readFileSync(SSL_CERT_PATH)
    };
  } catch (err) {
    console.error('Failed to load SSL certificate or key:', err.message);
    process.exit(1);
  }

  if (ENABLE_HTTP2) {
    const http2 = require('http2');
    http2.createSecureServer(sslOptions, handleRequest).listen(HTTPS_PORT, HOSTNAME, () => {
      console.log(`HTTP/2 server running at https://${HOSTNAME}:${HTTPS_PORT}/`);
    });
  } else {
    const https = require('https');
    https.createServer(sslOptions, handleRequest).listen(HTTPS_PORT, HOSTNAME, () => {
      console.log(`HTTPS server running at https://${HOSTNAME}:${HTTPS_PORT}/`);
    });
  }
}

if (ENABLE_HTTP || REDIRECT_HTTP_TO_HTTPS) {
  const http = require('http');
  const httpHandler = REDIRECT_HTTP_TO_HTTPS
    ? (req, res) => {
        const host = (req.headers.host && req.headers.host.split(':')[0]) || HOSTNAME;
        const location = `https://${host}:${HTTPS_PORT}${req.url}`;
        res.writeHead(301, { Location: location });
        res.end();
		logRequest(req, 301, 'Redirect to HTTPS');
      }
    : handleRequest;

  http.createServer(httpHandler).listen(HTTP_PORT, HOSTNAME, () => {
    console.log(
      REDIRECT_HTTP_TO_HTTPS
        ? `HTTP redirect server running at http://${HOSTNAME}:${HTTP_PORT}/`
        : `HTTP server running at http://${HOSTNAME}:${HTTP_PORT}/`
    );
  });
}
