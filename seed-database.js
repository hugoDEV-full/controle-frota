const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
require('dotenv').config();

async function seedDatabase() {
  console.log('🌱 Iniciando carga inicial do banco...');
  
  // Debug: mostrar variáveis disponíveis
  console.log('🔍 Variáveis de ambiente disponíveis:');
  console.log('  MYSQLURL:', process.env.MYSQLURL ? '✅' : '❌');
  console.log('  MYSQL_PUBLIC_URL:', process.env.MYSQL_PUBLIC_URL ? '✅' : '❌');
  console.log('  DATABASE_URL:', process.env.DATABASE_URL ? '✅' : '❌');
  console.log('🔍 Variáveis individuais:');
  console.log('  DB_HOST:', process.env.DB_HOST || '❌ não definido');
  console.log('  DB_USER:', process.env.DB_USER || '❌ não definido');
  console.log('  DB_PASSWORD:', process.env.DB_PASSWORD ? '✅' : '❌ não definido');
  
  // Railway fornece MYSQLURL ou MYSQL_PUBLIC_URL automaticamente
  // Vamos tentar também DATABASE_URL que é comum em algumas plataformas
  const mysqlUrl = process.env.MYSQLURL || process.env.MYSQL_PUBLIC_URL || process.env.DATABASE_URL;
  
  let connection;
  if (mysqlUrl) {
    console.log(`🔗 Usando ${process.env.MYSQLURL ? 'MYSQLURL' : 'MYSQL_PUBLIC_URL'} do Railway...`);
    // Parse da URL do Railway: mysql://user:password@host:port/database
    const url = new URL(mysqlUrl);
    connection = await mysql.createConnection({
      host: url.hostname,
      port: url.port || 3306,
      user: url.username,
      password: url.password,
      database: url.pathname.substring(1), // Remove o '/' inicial
      multipleStatements: true
    });
  } else {
    // Fallback para variáveis individuais (valores do Railway)
    console.log('🔧 Usando variáveis individuais...');
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'metro.proxy.rlwy.net',
      port: process.env.DB_PORT || 50518,
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || 'GQIKnsNgyIuwilsskpKOfeCXMIZaKFbR',
      database: process.env.DB_NAME || 'railway',
      multipleStatements: true
    });
  }

  try {
    // 1) Criar usuário admin com bcrypt
    console.log('👤 Criando usuário admin...');
    const hashedPassword = await bcrypt.hash('Bento1617@', 10);
    
    await connection.execute(`
      INSERT INTO usuarios (nome, email, senha, role, created_at) 
      VALUES ('Hugo Leonardo', 'hugo.leonardo.jobs@gmail.com', ?, 'admin', NOW())
      ON DUPLICATE KEY UPDATE senha = VALUES(senha), role = VALUES(role)
    `, [hashedPassword]);

    // 2) Inserir veículos de exemplo
    console.log('🚗 Inserindo veículos de exemplo...');
    const veiculos = [
      ['Fiesta', 'ABC-1234', 'Ford', 2020, 45000, 35000],
      ['Onix', 'DEF-5678', 'Chevrolet', 2021, 32000, 22000],
      ['Palio', 'GHI-9012', 'Fiat', 2019, 58000, 48000],
      ['Corolla', 'JKL-3456', 'Toyota', 2022, 15000, 5000],
      ['HB20', 'MNO-7890', 'Hyundai', 2020, 42000, 32000]
    ];

    for (const [nome, placa, marca, ano, km, ultimaTrocaOleo] of veiculos) {
      await connection.execute(`
        INSERT INTO veiculos (nome, placa, marca, ano, km, ultimaTrocaOleo, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, NOW())
        ON DUPLICATE KEY UPDATE 
          nome = VALUES(nome), 
          marca = VALUES(marca), 
          ano = VALUES(ano), 
          km = VALUES(km), 
          ultimaTrocaOleo = VALUES(ultimaTrocaOleo)
      `, [nome, placa, marca, ano, km, ultimaTrocaOleo]);
    }

    // 3) Inserir motoristas de exemplo
    console.log('👨‍✈️ Inserindo motoristas de exemplo...');
    const motoristas = [
      ['João Silva', '123.456.789-00', 'CNH123456', '2025-12-31', 'B', null],
      ['Maria Santos', '987.654.321-00', 'CNH654321', '2024-06-30', 'C', null],
      ['Carlos Oliveira', '456.789.123-00', 'CNH789123', '2025-08-15', 'AB', null],
      ['Ana Costa', '789.123.456-00', 'CNH321654', '2026-01-20', 'D', null],
      ['Pedro Lima', '321.654.987-00', 'CNH987321', '2024-11-10', 'B', null]
    ];

    for (const [nome, cpf, cnh, validade, categoria, foto_cnh] of motoristas) {
      await connection.execute(`
        INSERT INTO motoristas (nome, cpf, cnh, data_validade, categoria, foto_cnh, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, NOW())
        ON DUPLICATE KEY UPDATE 
          nome = VALUES(nome), 
          data_validade = VALUES(data_validade), 
          categoria = VALUES(categoria)
      `, [nome, cpf, cnh, validade, categoria, foto_cnh]);
    }

    // 4) Inserir alguns registros de uso de exemplo
    console.log('📊 Inserindo registros de uso...');
    const usos = [
      [1, 'João Silva', '2024-01-15 08:00:00', '2024-01-15 18:00:00', 45000, 45250, 'Trabalho'],
      [2, 'Maria Santos', '2024-01-16 09:00:00', '2024-01-16 17:30:00', 32000, 32180, 'Trabalho'],
      [3, 'Carlos Oliveira', '2024-01-17 07:30:00', '2024-01-17 19:00:00', 58000, 58320, 'Pessoal'],
      [1, 'João Silva', '2024-01-18 08:15:00', '2024-01-18 17:45:00', 45250, 45480, 'Trabalho'],
      [4, 'Ana Costa', '2024-01-19 10:00:00', '2024-01-19 16:00:00', 15000, 15120, 'Trabalho']
    ];

    for (const [veiculo_id, motorista, data_hora_inicial, data_hora_final, km_inicial, km_final, finalidade] of usos) {
      await connection.execute(`
        INSERT INTO uso_veiculos 
        (veiculo_id, motorista, data_hora_inicial, data_hora_final, km_inicial, km_final, finalidade, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
      `, [veiculo_id, motorista, data_hora_inicial, data_hora_final, km_inicial, km_final, finalidade]);
    }

    // 5) Inserir algumas multas de exemplo
    console.log('🚨 Inserindo multas de exemplo...');
    const multas = [
      [1, 'João Silva', '2024-01-15', 'Estacionar em local proibido', 150.00, 'Pendente'],
      [2, 'Maria Santos', '2024-01-16', 'Excesso de velocidade', 200.00, 'Paga'],
      [3, 'Carlos Oliveira', '2024-01-17', 'Avanço de sinal', 180.50, 'Pendente']
    ];

    for (const [veiculo_id, motorista, data, descricao, valor, status] of multas) {
      await connection.execute(`
        INSERT INTO multas 
        (veiculo_id, motorista, data, descricao, valor, status, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, NOW())
      `, [veiculo_id, motorista, data, descricao, valor, status]);
    }

    // 6) Inserir manutenções de exemplo
    console.log('🔧 Inserindo manutenções de exemplo...');
    const manutencoes = [
      [1, '2024-01-20', 'Troca de óleo', 150.00, 'Concluída', 'Troca de óleo e filtro'],
      [2, '2024-01-25', 'Revisão geral', 500.00, 'Pendente', 'Revisão dos 40.000 km'],
      [3, '2024-01-18', 'Alinhamento e balanceamento', 120.00, 'Concluída', 'Alinhamento direção e balanceamento']
    ];

    for (const [veiculo_id, data_agendada, tipo, custo, status, descricao] of manutencoes) {
      await connection.execute(`
        INSERT INTO manutencoes 
        (veiculo_id, data_agendada, tipo, custo, status, descricao, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, NOW())
      `, [veiculo_id, data_agendada, tipo, custo, status, descricao]);
    }

    console.log('✅ Carga inicial concluída com sucesso!');
    console.log('👤 Usuário admin: hugo.leonardo.jobs@gmail.com / Bento1617@');
    console.log('🚗 5 veículos inseridos');
    console.log('👨‍✈️ 5 motoristas inseridos');
    console.log('📊 5 registros de uso inseridos');
    console.log('🚨 3 multas inseridas');
    console.log('🔧 3 manutenções inseridas');

  } catch (err) {
    console.error('❌ Erro na carga inicial:', err);
    process.exit(1);
  } finally {
    await connection.end();
  }
}

if (require.main === module) {
  seedDatabase();
}

module.exports = { seedDatabase };
