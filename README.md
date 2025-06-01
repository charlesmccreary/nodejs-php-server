# nodejs-php-server
An experimental PHP server (in place of Nginx or Apache), implemented in Node.js.

### How to use this server:
1. Install Node.js
2. Install cgi-fcgi (`apt install libfcgi-bin` or `yum install fcgi`)
3. Install & configure PHP-FPM
4. Configure the variables at the top of the script
   - Set the hostname & ports
   - Set the root directory
   - Set your cert paths, if applicable
   - Set your PHP-FPM socket path
   - Enable or disable other options as needed
5. Run `node php-server.js`
6. Install a PHP application or modify public/index.php to do something useful
