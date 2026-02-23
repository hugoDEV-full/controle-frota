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
    multipleStatements: true
  });

  try {
    // 1) Criar banco controle_frota (se não existir)
    console.log('📦 Criando banco controle_frota (se não existir)...');
    await connection.execute(`CREATE DATABASE IF NOT EXISTS \`controle_frota\`;`);
    await connection.execute(`USE \`controle_frota\`;`);

    // 2) Importar estrutura
    const estruturaPath = './controle_frota_estrutura.sql';
    if (fs.existsSync(estruturaPath)) {
      console.log('📋 Importando estrutura...');
      const estruturaSQL = fs.readFileSync(estruturaPath, 'utf8');
      await connection.query(estruturaSQL);
      console.log('✅ Estrutura importada com sucesso.');
    } else {
      console.warn('⚠️ Arquivo de estrutura não encontrado:', estruturaPath);
    }

    // 3) Importar dados (se tiver dump completo)
    const dadosPath = './controle_frota_dump.sql';
    if (fs.existsSync(dadosPath)) {
      console.log('💾 Importando dados...');
      const dadosSQL = fs.readFileSync(dadosPath, 'utf8');
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
