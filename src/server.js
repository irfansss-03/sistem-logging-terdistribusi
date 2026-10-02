const Hapi = require('@hapi/hapi');
const { nanoid } = require('nanoid');
const crypto = require('crypto');
const fs = require('fs');

const logs = [];

const init = async () => {
  const server = Hapi.server({ port: 3000, host: '0.0.0.0' });

  // Endpoint POST untuk menerima log dari client
  server.route({
    method: 'POST',
    path: '/logs',
    handler: (request, h) => {
      const { source, message, timestamp, hash } = request.payload;

      // Validasi data
      if (!source || !message || !hash || !timestamp) {
        return h.response({ status: 'fail', message: 'Data tidak lengkap' }).code(400);
      }

      // Verifikasi hash
      const dataString = `${source}|${message}|${timestamp}`;
      const serverHash = crypto.createHash('sha256').update(dataString).digest('hex');

      if (serverHash !== hash) {
        return h.response({ status: 'fail', message: 'Hash tidak valid. Data mungkin diubah.' }).code(403);
      }

      // Simpan log
      const log = { id: nanoid(), source, message, timestamp };
      logs.push(log);
      fs.appendFileSync('logs.txt', `${JSON.stringify(log)}\n`);
      console.log("Log disimpan:", log);
      return h.response({ status: 'success', data: log }).code(201);
    }
  });

  // Endpoint GET untuk melihat semua log dari browser atau dashboard
  server.route({
    method: 'GET',
    path: '/logs',
    handler: (request, h) => {
      try {
        const rawData = fs.readFileSync('logs.txt', 'utf8');
        const lines = rawData.trim().split('\n');
        const data = lines.map(line => JSON.parse(line));
        return h.response(data).code(200);
      } catch (err) {
        return h.response({ status: 'fail', message: 'Gagal membaca log.' }).code(500);
      }
    }
  });

  await server.start();
  console.log('Server running on %s', server.info.uri);
};

init();
