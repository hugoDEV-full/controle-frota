const mysql = require('mysql2/promise');
const fs = require('fs');
require('dotenv').config();

async function setupDatabase() {
  console.log('🔧 Iniciando setup do banco de dados...');
  
  const connection = await mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME, // Conecta direto no banco existente
    multipleStatements: true
  });

  try {
    console.log(`📦 Usando banco existente: ${process.env.DB_NAME}`);

    // 1) Importar estrutura
    const estruturaPath = './controle_frota_estrutura.sql';
    if (fs.existsSync(estruturaPath)) {
      console.log('📋 Importando estrutura...');
      // Remove CREATE DATABASE e USE do SQL para evitar erro
      let estruturaSQL = fs.readFileSync(estruturaPath, 'utf8');
      estruturaSQL = estruturaSQL.replace(/CREATE DATABASE[^;]*;/gi, '');
      estruturaSQL = estruturaSQL.replace(/USE `[^`]*`;/gi, '');
      
      await connection.query(estruturaSQL);
      console.log('✅ Estrutura importada com sucesso.');
    } else {
      console.warn('⚠️ Arquivo de estrutura não encontrado:', estruturaPath);
    }

    // 2) Importar dados (se tiver dump completo)
    const dadosPath = './controle_frota_dump.sql';
    if (fs.existsSync(dadosPath)) {
      console.log('💾 Importando dados...');
      // Remove CREATE DATABASE e USE do SQL para evitar erro
      let dadosSQL = fs.readFileSync(dadosPath, 'utf8');
      dadosSQL = dadosSQL.replace(/CREATE DATABASE[^;]*;/gi, '');
      dadosSQL = dadosSQL.replace(/USE `[^`]*`;/gi, '');
      
      await connection.query(dadosSQL);
      console.log('✅ Dados importados com sucesso.');
    } else {
      console.warn('⚠️ Arquivo de dados não encontrado:', dadosPath);
    }

    console.log('🚀 Setup do banco concluído!');
  } catch (err) {
    console.error('❌ Erro no setup do banco:', err);
    process.exit(1);
  } finally {
    await connection.end();
  }
}

if (require.main === module) {
  setupDatabase();
}

module.exports = { setupDatabase };
