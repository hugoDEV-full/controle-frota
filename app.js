const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const mysql = require('mysql2');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const session = require('express-session');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();
//time zone
process.env.TZ = 'America/Sao_Paulo';
// Configura o servidor HTTP e integra o Socket.IO
const http = require('http');
const app = express();
const server = http.createServer(app);
const { Server } = require('socket.io');
const io = new Server(server, {
    cors: {
        // origin: ["https://rococo-kangaroo-21ce36.netlify.app", "http://127.0.0.1:5500", "http://localhost:3000"],
        origin: "*",
        methods: ["GET", "POST"]
    }
});


const port = 3000;


// Se a pasta 'uploads' não existir, cria ela
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// Cria um pool de conexões
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});


// Atribui o pool à variável db para compatibilidade nas requisições
const db = pool;

const util = require('util');
const query = util.promisify(db.query).bind(db);

// ===== Início do Servidor =====
//const express = require('express');
//const app = express();


/* Inicia o servidor imediatamente; o pool cuidadas conexões

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`App rodando na porta ${PORT}`);
}); */

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`App rodando na porta ${PORT}`);
});



// Middleware pra checar se o usuário é admin
function isAdmin(req, res, next) {
    if (req.isAuthenticated() && req.user.role === 'admin') {
        return next();
    }
    res.status(403).send("Acesso negado. Só admin pode fazer isso.");
}

// Config do multer pra upload de imagens
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Tipo de arquivo não permitido'), false);
        }
    }
});
const uploadMultiple = multer({
    storage: storage,
    limits: { fileSize: 1000 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Tipo de arquivo não permitido'), false);
        }
    }
}).array('foto_km');

// Configura o EJS e define a pasta das views
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');
// Libera acesso à pasta uploads e public
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Configuração das sessões e do Passport
app.use(session({
    secret: process.env.SECRET_SESSION,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 60 * 1000 } // 30 min inativos
}));

// Inicializa o Passport e vincula à sessão
app.use(passport.initialize());
app.use(passport.session());

// Configuração da estratégia local do Passport
passport.use(new LocalStrategy(
    { usernameField: 'email', passwordField: 'password' },
    (email, password, done) => {
        db.query("SELECT * FROM usuarios WHERE email = ?", [email], (err, results) => {
            if (err) return done(err);
            if (results.length === 0) {
                return done(null, false, { message: 'Usuário não encontrado.' });
            }
            const user = results[0];
            bcrypt.compare(password, user.senha, (err, isMatch) => {
                if (err) return done(err);
                if (isMatch) return done(null, user);
                return done(null, false, { message: 'Senha incorreta.' });
            });
        });
    }
));

// Serializa o usuário, armazenando apenas seu ID na sessão
passport.serializeUser((user, done) => {
    //console.log("Serializando usuário:", user);
    done(null, user.id);
});

// Desserializa o usuário a partir do ID armazenado, consultando o banco
passport.deserializeUser((id, done) => {
    db.query("SELECT * FROM usuarios WHERE id = ?", [id], (err, results) => {
        if (err) return done(err);
        if (results.length === 0) return done(null, false);
        //console.log("Desserializando usuário:", results[0]);
        return done(null, results[0]);
    });
});

// Middleware para garantir que o usuário esteja autenticado
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
}

// Rota de login com regeneração de sessão 
app.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) return next(err);
        if (!user) return res.redirect('/login');
        req.session.regenerate((err) => {
            if (err) return next(err);
            req.logIn(user, (err) => {
                if (err) return next(err);
                //console.log("Usuário logado com sucesso:", user);
                //console.log("Sessão após login:", req.session);
                return res.redirect('/');
            });
        });
    })(req, res, next);
});

// Tela de login
app.get('/login', (req, res) => {
    res.render('login', { layout: 'login' }); // layout exclusivo para login
});


// Rota de logout que destrói a sessão
app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) return next(err);
        req.session.destroy(() => {
            console.log("Sessão encerrada. Usuário deslogado.");
            res.redirect('/login');
        });
    });
});
/* Funções de notificação */

// Manda um email avisando que o veículo precisa de troca de óleo
function sendOilChangeEmail(veiculo) {
    const transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });
    const mailOptions = {
        to: process.env.NOTIFY_EMAIL || process.env.EMAIL_USER,
        from: process.env.EMAIL_USER,
        subject: `Troca de Óleo Necessária: ${veiculo.nome} - ${veiculo.placa}`,
        text: `O veículo ${veiculo.nome} (Placa: ${veiculo.placa}) atingiu ${veiculo.km} km, com a última troca de óleo em ${veiculo.ultimaTrocaOleo}. Bora agendar a manutenção!`
    };
    transporter.sendMail(mailOptions, (err, info) => {
        if (err) console.error("Erro ao enviar email:", err);
        else console.log("Email enviado:", info.response);
    });
}

// Checa se o veículo já rodou o suficiente pra precisar de troca de óleo
function checkOilChangeForVehicle(veiculo_id) {
    const query = `SELECT * FROM veiculos WHERE id = ?`;
    db.query(query, [veiculo_id], (err, results) => {
        if (err) {
            console.error("Erro na checagem de óleo:", err);
            return;
        }
        if (results.length > 0) {
            const veiculo = results[0];
            const km = Number(veiculo.km);
            const ultimaTroca = Number(veiculo.ultimaTrocaOleo);
            console.log(`Checando veículo ${veiculo.id}: km=${km}, última troca=${ultimaTroca}, diff=${km - ultimaTroca}`);
            if ((km - ultimaTroca) >= 10000) {
                io.emit('oilChangeNotification', veiculo);
                sendOilChangeEmail(veiculo);
            }
        }
    });
}



// injetar active page global caso nao tenha 

app.use((req, res, next) => {
    res.locals.activePage = res.locals.activePage || '';
    next();
});


//const util = require('util');
//const query = util.promisify(db.query).bind(db);

app.get('/', isAuthenticated, async (req, res) => {
    try {
        // Consultas para motoristas (contagem e dados)
        const validosResult = await query(
            'SELECT COUNT(*) AS totalValidos FROM motoristas WHERE data_validade >= CURDATE()'
        );
        const invalidosResult = await query(
            'SELECT COUNT(*) AS totalInvalidos FROM motoristas WHERE data_validade < CURDATE()'
        );
        const motoristasValidosList = await query(
            'SELECT nome, email, DATE_FORMAT(data_validade, "%d/%m/%Y") AS validade FROM motoristas WHERE data_validade >= CURDATE()'
        );
        const motoristasInvalidosList = await query(
            'SELECT nome, email, DATE_FORMAT(data_validade, "%d/%m/%Y") AS validade FROM motoristas WHERE data_validade < CURDATE()'
        );


        // Consultas para veículos e outras estatísticas
        const veiculosResult = await query('SELECT * FROM veiculos');
        const totalVeiculosResult = await query('SELECT COUNT(*) AS totalVeiculos FROM veiculos');
        const totalMultasResult = await query('SELECT COUNT(*) AS totalMultas FROM multas');
        const totalUsoResult = await query('SELECT COUNT(*) AS totalUso FROM uso_veiculos');
        const totalMotoristasResult = await query(
            'SELECT COUNT(DISTINCT motorista) AS totalMotoristasAtivos FROM uso_veiculos'
        );

        // Relatório: Uso por Dia
        const usoDiaResult = await query(`
          SELECT 
            DATE(data_criacao) AS dia, 
            COUNT(*) AS totalUsoDia,
            MIN(TIME(data_criacao)) AS primeiroUso,
            MAX(TIME(data_criacao)) AS ultimoUso
          FROM uso_veiculos
          GROUP BY DATE(data_criacao)
          ORDER BY dia DESC
        `);

        // Relatório: Uso por Mês
        const usoMesResult = await query(`
          SELECT DATE_FORMAT(data_criacao, '%Y-%m') AS mes, COUNT(*) AS totalUsoMes
          FROM uso_veiculos
          GROUP BY DATE_FORMAT(data_criacao, '%Y-%m')
          ORDER BY mes DESC
        `);

        // Relatório: Uso por Ano
        const usoAnoResult = await query(`
          SELECT YEAR(data_criacao) AS ano, COUNT(*) AS totalUsoAno
          FROM uso_veiculos
          GROUP BY YEAR(data_criacao)
          ORDER BY ano DESC
        `);

        // Relatório: Total de Uso no Ano Corrente
        const currentYear = new Date().getFullYear();
        const usoAnoAtualResult = await query(
            `SELECT COUNT(*) AS totalUsoAnoAtual FROM uso_veiculos WHERE YEAR(data_criacao) = ?`,
            [currentYear]
        );

        // Relatório: Multas por Mês
        const multasMesResult = await query(`
          SELECT DATE_FORMAT(data, '%Y-%m') AS mes, COUNT(*) AS totalMultasMes
          FROM multas
          GROUP BY DATE_FORMAT(data, '%Y-%m')
          ORDER BY mes DESC
        `);

        // Relatório: Multas por Ano
        const multasAnoResult = await query(`
          SELECT YEAR(data) AS ano, COUNT(*) AS totalMultasAno
          FROM multas
          GROUP BY YEAR(data)
          ORDER BY ano DESC
        `);

        // Relatório: Multas por Motorista
        const multasMotoristaResult = await query(`
          SELECT motorista, COUNT(*) AS totalMultasMotorista
          FROM multas
          GROUP BY motorista
          ORDER BY totalMultasMotorista DESC
        `);

        // Nova funcionalidade: Manutenções pendentes
        const manutencoesPendentes = await query(`
          SELECT m.*, v.placa, v.nome as veiculo_nome 
          FROM manutencoes m
          JOIN veiculos v ON m.veiculo_id = v.id
          WHERE m.status = 'pendente'
          ORDER BY m.data_agendada ASC
        `);

        res.render('dashboard', {
            title: 'Dashboard',
            layout: 'layout',
            activePage: 'dashboard',
            veiculos: veiculosResult,
            user: req.user,
            totalVeiculos: totalVeiculosResult[0].totalVeiculos,
            totalMultas: totalMultasResult[0].totalMultas,
            totalUso: totalUsoResult[0].totalUso,
            totalMotoristasAtivos: totalMotoristasResult[0].totalMotoristasAtivos,
            totalMotoristasValidos: validosResult[0].totalValidos,
            totalMotoristasInvalidos: invalidosResult[0].totalInvalidos,
            motoristasValidosList,   // Lista com nome e email dos motoristas com CNH válida
            motoristasInvalidosList, // Lista com nome e email dos motoristas com CNH vencida
            usoDia: usoDiaResult,
            usoMes: usoMesResult,
            usoAno: usoAnoResult,
            totalUsoAnoAtual: usoAnoAtualResult[0].totalUsoAnoAtual,
            multasMes: multasMesResult,
            multasAno: multasAnoResult,
            multasMotorista: multasMotoristaResult,
            manutencoesPendentes // Dados das manutenções pendentes
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro no servidor');
    }
});










// Tela de esqueci minha senha
app.get('/forgot-password', (req, res) => {
    res.render('forgot-password', { layout: 'forgot-password' });
});
app.post('/forgot-password', (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).send("Email é obrigatório.");

    crypto.randomBytes(20, (err, buffer) => {
        if (err) return res.status(500).send("Erro ao gerar token.");
        const token = buffer.toString('hex');
        const expires = Date.now() + 3600000; // 1 hora

        db.query("UPDATE usuarios SET password_reset_token = ?, password_reset_expires = ? WHERE email = ?", [token, expires, email], (err, result) => {
            if (err) return res.status(500).send("Erro no servidor.");
            if (result.affectedRows === 0) return res.status(400).send("Usuário não encontrado.");

            const transporter = nodemailer.createTransport({
                service: 'Gmail',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS
                }
            });

            const mailOptions = {
                to: email,
                from: process.env.EMAIL_USER,
                subject: 'Redefinição de Senha',
                text: `Você pediu pra resetar sua senha.\n\n` +
                    `Clica ou copia esse link no seu navegador:\n\n` +
                    `http://${req.headers.host}/reset-password/${token}\n\n` +
                    `Se não foi você, ignora esse email.\n`
            };

            transporter.sendMail(mailOptions, (err) => {
                if (err) return res.status(500).send("Erro ao enviar email.");
                res.send("Email enviado com instruções pra resetar sua senha.");
            });
        });
    });
});

// Tela de reset de senha
app.get('/reset-password/:token', (req, res) => {
    const { token } = req.params;
    db.query("SELECT * FROM usuarios WHERE password_reset_token = ? AND password_reset_expires > ?", [token, Date.now()], (err, results) => {
        if (err) return res.status(500).send("Erro no servidor.");
        if (results.length === 0) return res.status(400).send("Token inválido ou expirado.");
        res.render('reset-password', { layout: 'reset-password', token });
    });
});
app.post('/reset-password/:token', (req, res) => {
    const { token } = req.params;
    const { password } = req.body;
    if (!password) return res.status(400).send("Senha é obrigatória.");

    db.query("SELECT * FROM usuarios WHERE password_reset_token = ? AND password_reset_expires > ?", [token, Date.now()], (err, results) => {
        if (err) return res.status(500).send("Erro no servidor.");
        if (results.length === 0) return res.status(400).send("Token inválido ou expirado.");
        const user = results[0];

        bcrypt.hash(password, 10, (err, hash) => {
            if (err) return res.status(500).send("Erro ao atualizar senha.");
            db.query("UPDATE usuarios SET senha = ?, password_reset_token = NULL, password_reset_expires = NULL WHERE id = ?", [hash, user.id], (err, result) => {
                if (err) return res.status(500).send("Erro ao atualizar senha.");
                res.send("Senha atualizada! Já pode fazer login.");
            });
        });
    });
});


/*
app.get('/perfil', isAuthenticated, (req, res) => {
    res.render('perfil', { user: req.user });
});
app.get('/index2', isAuthenticated, (req, res) => {
    res.render('index2', { user: req.user });
}); */

/* Rotas de uso, veículos, multas, etc. */
// (A rota pra registrar uso do veículo tá comentada aqui, mas fica aí como referência)

/*
app.post('/usar/:id', isAuthenticated, upload.single('foto_km'), (req, res) => {
    // Código pra registrar uso do veículo...
});
*/

app.get('/relatorio-uso', isAuthenticated, (req, res) => {
    res.render('relatorio_uso', {
        title: 'Relatório de uso de veículos',
        layout: 'layout',
        activePage: 'relatorio_uso'
    });
});

app.get('/api/relatorio-uso', isAuthenticated, (req, res) => {
    // Parâmetros do DataTables
    let draw = req.query.draw || 0;
    let start = parseInt(req.query.start) || 0;
    let length = parseInt(req.query.length) || 10;
    let searchValue = req.query.search ? req.query.search.value : '';

    // Mapeamento dos índices para as colunas ordenáveis
    // Ordem visual da tabela:
    // 0: Checkbox (não ordenável)
    // 1: Veículo (veiculos.placa)
    // 2: Motorista (uso_veiculos.motorista)
    // 3: KM Inicial (uso_veiculos.km_inicial)
    // 4: KM Final (uso_veiculos.km_final)
    // 5: Data de Início (data_hora_inicial)
    // 6: Data de Fim (data_hora_final)
    // 7: Data de Criação (data_criacao)
    // 8: Foto de Quilometragem (não ordenável)
    // 9: Multas (não ordenável)
    // 10: Ações (não ordenável)
    let columns = [
        null,
        'veiculos.placa',
        'uso_veiculos.motorista',
        'uso_veiculos.km_inicial',
        'uso_veiculos.km_final',
        'data_hora_inicial',
        'data_hora_final',
        'data_criacao'
    ];

    // Obtém o índice da coluna para ordenação
    let orderColumnIndex = 1; // padrão
    let orderDir = 'asc'; // padrão
    if (req.query.order && req.query.order[0]) {
        orderColumnIndex = parseInt(req.query.order[0].column);
        orderDir = req.query.order[0].dir || 'asc';
    }
    // Se o índice não estiver entre 1 e 7 (colunas ordenáveis), define padrão
    if (orderColumnIndex < 1 || orderColumnIndex > 7) {
        orderColumnIndex = 5; // data_hora_inicial
    }
    let orderColumn = columns[orderColumnIndex] || 'data_hora_inicial';

    // Monta a cláusula WHERE se houver busca
    let whereClause = '';
    let params = [];
    if (searchValue) {
        whereClause = `WHERE (veiculos.placa LIKE ? OR uso_veiculos.motorista LIKE ? OR uso_veiculos.km_inicial LIKE ? OR uso_veiculos.km_final LIKE ? )`;
        const searchParam = '%' + searchValue + '%';
        params.push(searchParam, searchParam, searchParam, searchParam);
    }

    // Consulta principal
    let sql = `
      SELECT uso_veiculos.*, 
             veiculos.placa, 
             uso_veiculos.data_criacao, 
             GROUP_CONCAT(multas.multa SEPARATOR ", ") AS multas
      FROM uso_veiculos
      JOIN veiculos ON uso_veiculos.veiculo_id = veiculos.id
      LEFT JOIN multas ON uso_veiculos.id = multas.uso_id
      ${whereClause}
      GROUP BY uso_veiculos.id
      ORDER BY ${orderColumn} ${orderDir}
      LIMIT ? OFFSET ?
    `;
    // Adiciona os parâmetros para LIMIT e OFFSET
    params.push(length, start);

    //console.log("SQL principal:", sql);
    //console.log("Parâmetros:", params);

    db.query(sql, params, (err, results) => {
        if (err) {
            console.error("Erro na consulta principal:", err);
            return res.status(500).json({ error: "Erro na consulta principal" });
        }

        // Consulta para obter a contagem dos registros filtrados
        let countSql = `
        SELECT COUNT(DISTINCT uso_veiculos.id) AS total 
        FROM uso_veiculos
        JOIN veiculos ON uso_veiculos.veiculo_id = veiculos.id
        LEFT JOIN multas ON uso_veiculos.id = multas.uso_id
        ${whereClause}
      `;
        // Se houver busca, utiliza os primeiros 4 parâmetros; caso contrário, nenhum
        let countParams = searchValue ? params.slice(0, 4) : [];

        //console.log("SQL contagem filtrada:", countSql);
        //console.log("Parâmetros contagem:", countParams);

        db.query(countSql, countParams, (err, countResult) => {
            if (err) {
                console.error("Erro na consulta de contagem filtrada:", err);
                return res.status(500).json({ error: "Erro na consulta de contagem filtrada" });
            }
            let totalRecords = countResult[0].total;

            // Consulta para obter o total de registros (sem filtro)
            db.query('SELECT COUNT(*) AS total FROM uso_veiculos', (err, totalResult) => {
                if (err) {
                    console.error("Erro na consulta de contagem total:", err);
                    return res.status(500).json({ error: "Erro na consulta de contagem total" });
                }
                let totalRecordsUnfiltered = totalResult[0].total;
                // Envia o JSON no formato esperado pelo DataTables
                res.json({
                    draw: parseInt(draw),
                    recordsTotal: totalRecordsUnfiltered,
                    recordsFiltered: totalRecords,
                    data: results
                });
            });
        });
    });
});


app.get('/registrar-veiculo', isAuthenticated, isAdmin, (req, res) => {
    res.render('registrar-veiculo', {
        title: 'Registrar veículo',
        layout: 'layout',
        activePage: 'registrar-veiculo',
        user: req.user
    });
});
app.post('/registrar-veiculo', isAuthenticated, isAdmin, (req, res) => {
    const { nome, placa, km, ultimaTrocaOleo, emUsoPor, modelo } = req.body;
    if (!nome || !placa || !km || !ultimaTrocaOleo || !modelo) {
        return res.status(400).send('Todos os campos são obrigatórios');
    }
    db.query('INSERT INTO veiculos (nome, placa, km, ultimaTrocaOleo, emUsoPor, modelo) VALUES (?, ?, ?, ?, ?, ?)',
        [nome, placa, km, ultimaTrocaOleo, emUsoPor, modelo], (err, result) => {
            if (err) {
                console.error('Erro ao registrar veículo:', err);
                return res.status(500).send('Erro ao registrar veículo');
            }
            res.redirect('/');
        }
    );
});

app.post('/multar/:uso_id', isAuthenticated, (req, res) => {
    const { uso_id } = req.params;
    const { multa } = req.body; // Descrição da multa

    if (!multa) {
        return res.status(400).send("Descrição da multa é obrigatória.");
    }

    // Busca o uso pra saber o motorista e o veículo
    db.query("SELECT * FROM uso_veiculos WHERE id = ?", [uso_id], (err, usoResult) => {
        if (err) {
            console.error("Erro ao buscar uso:", err);
            return res.status(500).send("Erro ao buscar o uso.");
        }
        if (usoResult.length === 0) {
            return res.status(404).send("Uso não encontrado.");
        }

        const uso = usoResult[0];
        const motoristaProvavel = uso.motorista;
        const veiculo_id = uso.veiculo_id;

        // Insere a multa associando o uso e o motorista
        db.query(
            "INSERT INTO multas (veiculo_id, motorista, multa, uso_id) VALUES (?, ?, ?, ?)",
            [veiculo_id, motoristaProvavel, multa, uso_id],
            (err, result) => {
                if (err) {
                    console.error("Erro ao registrar a multa:", err);
                    return res.status(500).send("Erro ao registrar a multa.");
                }
                res.redirect("/relatorio-uso");
            }
        );
    });
});

// Rota pra mostrar o form de multa pra um veículo
app.get('/registrar-multa/:veiculo_id', isAuthenticated, (req, res) => {
    const { veiculo_id } = req.params;
    // Busca os dados do veículo
    db.query("SELECT * FROM veiculos WHERE id = ?", [veiculo_id], (err, veiculoResult) => {
        if (err) {
            console.error("Erro ao buscar veículo:", err);
            return res.status(500).send("Erro ao buscar o veículo.");
        }
        if (veiculoResult.length === 0) {
            return res.status(404).send("Veículo não encontrado.");
        }
        const veiculo = veiculoResult[0];
        res.render('registrarMulta', {
            veiculo,
            mensagemErro: null,
            title: 'Registro de Multa',
            layout: 'layout',
            activePage: 'registrarMulta'
        });
    });
});


app.post('/registrar-multa/:veiculo_id', isAuthenticated, isAdmin, (req, res) => {
    const { veiculo_id } = req.params;
    const { data_multa, multa } = req.body;

    if (!data_multa || !multa) {
        return res.status(400).send("Campos obrigatórios não preenchidos.");
    }

    // Converte a data da multa pra objeto Date
    const dataMulta = new Date(data_multa);

    /* 
      Procura um uso do veículo que englobe o horário da multa:
      - Início do uso <= data da multa 
      - E fim do uso é nulo ou >= data da multa
      Pega o uso mais recente que satisfaça essa condição.
    */
    const queryUso = `
      SELECT * FROM uso_veiculos 
      WHERE veiculo_id = ? 
        AND data_hora_inicial <= ? 
        AND (data_hora_final IS NULL OR data_hora_final >= ?)
      ORDER BY data_hora_inicial DESC 
      LIMIT 1
    `;

    db.query(queryUso, [veiculo_id, dataMulta, dataMulta], (err, usoResult) => {
        if (err) {
            console.error("Erro ao buscar uso do veículo:", err);
            return res.status(500).send("Erro ao buscar o uso.");
        }

        let motoristaProvavel = "Desconhecido";
        let uso_id = null;
        if (usoResult.length > 0) {
            const uso = usoResult[0];
            motoristaProvavel = uso.motorista;
            uso_id = uso.id;
        }

        if (!uso_id) {
            return res.render('mensagemMulta', {
                mensagem: "Não rolou associar um motorista. Cadastre um uso pra esse período."
            });
        }

        // Insere a multa com os dados informados
        const insertQuery = "INSERT INTO multas (veiculo_id, motorista, data, multa, uso_id) VALUES (?, ?, ?, ?, ?)";
        db.query(insertQuery, [veiculo_id, motoristaProvavel, data_multa, multa, uso_id], (err, result) => {
            if (err) {
                console.error("Erro ao registrar a multa:", err);
                return res.status(500).send("Erro ao registrar a multa.");
            }
            res.redirect("/relatorio-multas");
        });
    });
});

app.get('/relatorio-multas', isAuthenticated, (req, res) => {
    const query = `
      SELECT m.*, v.placa, u.data_hora_inicial, u.data_hora_final
      FROM multas m
      JOIN veiculos v ON m.veiculo_id = v.id
      LEFT JOIN uso_veiculos u ON m.uso_id = u.id
      ORDER BY m.data DESC
    `;
    db.query(query, (err, multasResult) => {
        if (err) {
            console.error("Erro ao buscar multas:", err);
            return res.status(500).send("Erro ao buscar multas.");
        }
        res.render('relatorioMultas', {
            multas: multasResult,
            title: 'Relatório de Multas',
            layout: 'layout',
            activePage: 'relatorioMultas'
        });
    });
});

app.get('/editar-uso/:id', isAuthenticated, (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM uso_veiculos WHERE id = ?', [id], (err, usoResult) => {
        if (err) {
            console.error('Erro ao buscar uso:', err);
            return res.status(500).send('Erro ao buscar dados do uso');
        }
        if (usoResult.length === 0) {
            return res.status(404).send('Uso não encontrado');
        }
        const uso = usoResult[0];
        // Pega as multas relacionadas a esse uso
        db.query('SELECT * FROM multas WHERE uso_id = ?', [id], (err, multasResult) => {
            if (err) {
                console.error('Erro ao buscar multas:', err);
                return res.status(500).send('Erro ao buscar multas');
            }
            res.render('editarUso', {
                uso,
                multas: multasResult,
                title: 'Editar Uso',
                layout: 'layout',
                activePage: 'editarUso'
            });
        });
    });
});


app.get('/usar/:id', isAuthenticated, (req, res) => {
    const { id } = req.params;
    const userId = req.user.id; // Pega o ID do usuário autenticado

    // Busca o email do usuário autenticado
    db.query('SELECT email FROM usuarios WHERE id = ?', [userId], (err, userResult) => {
        if (err) {
            console.error("Erro ao buscar usuário:", err);
            return res.status(500).send("Erro ao buscar usuário.");
        }
        if (userResult.length === 0) {
            return res.status(404).send("Usuário não encontrado");
        }

        const motoristaEmail = userResult[0].email; // Email do usuário autenticado

        // Busca os dados do veículo
        db.query('SELECT * FROM veiculos WHERE id = ?', [id], (err, veiculoResult) => {
            if (err) {
                console.error("Erro ao buscar veículo:", err);
                return res.status(500).send("Erro ao buscar o veículo.");
            }
            if (veiculoResult.length === 0) {
                return res.status(404).send("Veículo não encontrado");
            }

            const veiculo = veiculoResult[0];
            const kmInicial = veiculo.km || 0;

            res.render('usar', {
                veiculo,
                kmInicial,
                motoristaEmail, // Passa o email do usuário autenticado
                title: 'Usar Veículo',
                layout: 'layout',
                activePage: 'usar'
            });
        });
    });
});

//rota para auto gerar manutenção

function autoGenerateMaintenance(veiculo) {
    console.log(`🔍 Verificando manutenção para veículo ${veiculo.id} (${veiculo.placa}) com KM=${veiculo.km}`);

    const regrasManutencao = [
        { tipo: 'Troca de Pneus', kmIntervalo: 100 },
        { tipo: 'Rodízio de Pneus', kmIntervalo: 100 },
        { tipo: 'Troca de Pastilhas', kmIntervalo: 100 },
        { tipo: 'Troca de Discos de Freio', kmIntervalo: 100 },
    ];

    regrasManutencao.forEach(regra => {
        if (Number(veiculo.km) >= regra.kmIntervalo) {
            console.log(`⚠️ Veículo ${veiculo.id} ultrapassou ${regra.kmIntervalo} km para ${regra.tipo}`);

            const queryVerifica = `
              SELECT * FROM manutencoes 
              WHERE veiculo_id = ? AND tipo = ? AND status = 'pendente'
            `;
            db.query(queryVerifica, [veiculo.id, regra.tipo], (err, results) => {
                if (err) {
                    console.error(`Erro ao verificar manutenção ${regra.tipo}:`, err);
                    return;
                }
                console.log(`Resultado da verificação para ${regra.tipo}: ${results.length} registros encontrados.`);
                if (results.length === 0) {
                    const descricao = `Manutenção automática disparada ao atingir ${veiculo.km} km.`;
                    const queryInsert = `
                       INSERT INTO manutencoes (veiculo_id, tipo, descricao, km_agendado, status)
                       VALUES (?, ?, ?, ?, 'pendente')
                    `;
                    console.log(`Tentando inserir manutenção "${regra.tipo}" para o veículo ${veiculo.placa}.`);
                    db.query(queryInsert, [veiculo.id, regra.tipo, descricao, regra.kmIntervalo], (err, result) => {
                        if (err) {
                            console.error(`Erro ao inserir manutenção ${regra.tipo}:`, err);
                        } else {
                            console.log(`✅ Manutenção "${regra.tipo}" gerada para o veículo ${veiculo.placa}.`);
                            sendMaintenanceNotification(veiculo, { tipo: regra.tipo, descricao });
                        }
                    });
                } else {
                    console.log(`✅ Já existe manutenção pendente para ${regra.tipo} no veículo ${veiculo.placa}.`);
                }
            });
        } else {
            console.log(`Veículo ${veiculo.id} com KM=${veiculo.km} não atingiu ${regra.kmIntervalo} para ${regra.tipo}.`);
        }
    });
}


// Rota para registrar o uso do veículo, atualizar km e disparar manutenções automáticas
app.post('/usar/:id', isAuthenticated, upload.single('foto_km'), (req, res) => {
    const { id } = req.params; // ID do veículo
    const { km_inicial, km_final, data_hora_inicial, data_hora_final } = req.body;
    const foto_km = req.file ? req.file.filename : null;
    const motoristaEmail = req.user.email; // Email do usuário autenticado

    if (!km_inicial) {
        return res.status(400).send('Campos obrigatórios faltando');
    }

    // Busca os dados do veículo
    db.query('SELECT * FROM veiculos WHERE id = ?', [id], (err, veiculoResult) => {
        if (err) {
            console.error("Erro ao buscar veículo:", err);
            return res.status(500).send("Erro ao buscar o veículo.");
        }
        if (veiculoResult.length === 0) {
            return res.status(404).send("Veículo não encontrado");
        }
        const veiculo = veiculoResult[0];

        // Valida o km_inicial
        const expectedKmInicial = veiculo.km;
        const kmInicialParsed = parseInt(km_inicial, 10);
        if (kmInicialParsed !== expectedKmInicial) {
            return res.status(400).send("Erro: O km inicial deve ser igual ao km atual do veículo.");
        }

        // Converte e valida o km_final
        const kmFinalParsed = parseInt(km_final, 10);
        const kmFinalValue = (km_final === '' || isNaN(kmFinalParsed)) ? null : kmFinalParsed;
        if (kmFinalValue !== null && kmFinalValue < kmInicialParsed) {
            return res.status(400).send("Erro: km final não pode ser menor que km inicial");
        }

        const dataHoraInicial = new Date(data_hora_inicial);
        const dataHoraFinal = data_hora_final ? new Date(data_hora_final) : null;
        const newEnd = dataHoraFinal ? dataHoraFinal : new Date('9999-12-31');

        // Verifica o cadastro de motoristas
        db.query('SELECT * FROM motoristas WHERE email = ?', [motoristaEmail], (err, motoristaResult) => {
            if (err) {
                console.error("Erro ao buscar motorista:", err);
                return res.status(500).send("Erro ao buscar o motorista.");
            }
            if (motoristaResult.length === 0) {
                return res.status(400).send("Erro: Usuário não possui cadastro de motorista.");
            }
            const motoristasComCNHValida = motoristaResult.filter(motorista => {
                return new Date(motorista.data_validade) >= new Date();
            });
            if (motoristasComCNHValida.length === 0) {
                return res.status(400).send("Erro: A CNH do motorista está vencida.");
            }

            // Verifica sobreposição de uso
            db.query(
                `SELECT * FROM uso_veiculos 
           WHERE (veiculo_id = ? OR motorista = ?)
             AND (data_hora_inicial < ?)
             AND ((data_hora_final IS NULL) OR (data_hora_final > ?))`,
                [id, motoristaEmail, newEnd, dataHoraInicial],
                (err, overlapResult) => {
                    if (err) {
                        console.error("Erro na verificação de sobreposição:", err);
                        return res.status(500).send("Erro interno");
                    }
                    if (overlapResult.length > 0) {
                        return res.status(400).send("Erro: Já existe um uso nesse período.");
                    }

                    // Insere o registro de uso
                    db.query(
                        'INSERT INTO uso_veiculos (veiculo_id, motorista, km_inicial, km_final, data_hora_inicial, data_hora_final, foto_km) VALUES (?, ?, ?, ?, ?, ?, ?)',
                        [id, motoristaEmail, km_inicial, kmFinalValue, dataHoraInicial, dataHoraFinal, foto_km],
                        (err, result) => {
                            if (err) throw err;

                            // Se km_final for informado, atualiza o km do veículo e dispara verificações
                            if (kmFinalValue !== null) {
                                db.query('UPDATE veiculos SET km = ? WHERE id = ?', [kmFinalValue, id], (err, result2) => {
                                    if (err) {
                                        console.error("Erro ao atualizar km:", err);
                                    } else {
                                        console.log(`🚗 Veículo ${id} atualizado para km=${kmFinalValue}`);
                                        // Verifica troca de óleo
                                        checkOilChangeForVehicle(id);
                                        // Busca dados atualizados do veículo e chama autoGenerateMaintenance
                                        db.query('SELECT * FROM veiculos WHERE id = ?', [id], (err, updatedResult) => {
                                            if (err) {
                                                console.error("Erro ao buscar veículo atualizado:", err);
                                            } else if (updatedResult.length > 0) {
                                                console.log("📊 Dados atualizados do veículo:", updatedResult[0]);
                                                autoGenerateMaintenance(updatedResult[0]);
                                            }
                                        });
                                    }
                                });
                            }
                            res.redirect('/');
                        }
                    );
                }
            );
        });
    });
});





// Rota para editar uso, atualizar multas e imagem  
app.post('/editar-uso/:id', isAuthenticated, uploadMultiple, (req, res) => {
    const { id } = req.params;
    const { motorista, km_final, data_hora_final, multas_id, multas_descricao } = req.body;
    const novasMultas = req.body.novasMultas
        ? [].concat(req.body.novasMultas).filter(m => m.trim().length > 0)
        : [];

    let updateQuery, params;
    if (req.files && req.files.length > 0) {
        const novaImagem = req.files[0].filename;
        updateQuery = `
          UPDATE uso_veiculos 
          SET motorista = ?, km_final = ?, data_hora_final = ?, foto_km = ? 
          WHERE id = ?
      `;
        params = [
            motorista,
            km_final === '' ? null : km_final,
            data_hora_final === '' ? null : data_hora_final,
            novaImagem,
            id
        ];
    } else {
        updateQuery = `
          UPDATE uso_veiculos 
          SET motorista = ?, km_final = ?, data_hora_final = ? 
          WHERE id = ?
      `;
        params = [
            motorista,
            km_final === '' ? null : km_final,
            data_hora_final === '' ? null : data_hora_final,
            id
        ];
    }

    // Função auxiliar para renderizar o formulário com uma mensagem de erro amigável
    function renderError(message) {
        db.query("SELECT * FROM uso_veiculos WHERE id = ?", [id], (err, results) => {
            if (err || results.length === 0) {
                return res.status(500).send("Erro ao carregar os dados para exibição do erro.");
            }
            const uso = results[0];
            // Renderiza a view 'editarUso' passando o objeto 'uso' e a mensagem de erro
            res.render('editarUso', { uso, errorMessage: message });
        });
    }

    // Valida km_final e data_hora_final, se informados
    if ((km_final && km_final !== '') || (data_hora_final && data_hora_final !== '')) {
        db.query("SELECT km_inicial, data_hora_inicial FROM uso_veiculos WHERE id = ?", [id], (err, resultSelect) => {
            if (err) {
                console.error("Erro na verificação:", err);
                return renderError("Erro interno ao verificar os dados.");
            }
            if (resultSelect.length > 0) {
                const kmInicialValue = parseInt(resultSelect[0].km_inicial, 10);
                if (km_final && km_final !== '') {
                    const kmFinalParsed = parseInt(km_final, 10);
                    if (isNaN(kmFinalParsed)) {
                        return renderError('KM final inválido.');
                    }
                    if (kmFinalParsed < kmInicialValue) {
                        return renderError('KM final não pode ser menor que KM inicial.');
                    }

                    // Verificar autonomia < 700
                    const autonomiaUno = 700;
                    const consumo = kmFinalParsed - kmInicialValue;
                    if (consumo > autonomiaUno) {
                        return renderError(`O consumo (${consumo} km) ultrapassa a autonomia máxima de um tanque (${autonomiaUno} km).`);
                    }
                }
                if (data_hora_final && data_hora_final !== '') {
                    const dataHoraFinalParsed = new Date(data_hora_final);
                    const dataHoraInicialParsed = new Date(resultSelect[0].data_hora_inicial);
                    if (dataHoraFinalParsed < dataHoraInicialParsed) {
                        return renderError('A data final não pode ser antes da data inicial.');
                    }
                }
            }
            executeUpdate();
        });
    } else {
        executeUpdate();
    }

    function executeUpdate() {
        db.query(updateQuery, params, (err, result) => {
            if (err) {
                console.error("Erro ao atualizar uso:", err);
                return renderError('Erro ao atualizar o uso. Por favor, tente novamente.');
            }

            // Atualiza as multas já existentes
            if (multas_id && multas_descricao) {
                const ids = Array.isArray(multas_id) ? multas_id : [multas_id];
                const descricoes = Array.isArray(multas_descricao) ? multas_descricao : [multas_descricao];
                ids.forEach((multaId, index) => {
                    db.query(
                        'UPDATE multas SET multa = ? WHERE id = ?',
                        [descricoes[index], multaId],
                        (err) => {
                            if (err) console.error(`Erro ao atualizar multa ${multaId}:`, err);
                        }
                    );
                });
            }

            // Se tiver km_final, atualiza o km do veículo e dispara a verificação de manutenção
            if (km_final && km_final !== '') {
                const kmFinalParsed = parseInt(km_final, 10);
                const kmFinalValue = isNaN(kmFinalParsed) ? null : kmFinalParsed;
                if (kmFinalValue !== null) {
                    db.query("SELECT veiculo_id FROM uso_veiculos WHERE id = ?", [id], (err, result2) => {
                        if (err) {
                            console.error("Erro ao buscar veiculo_id:", err);
                        } else if (result2.length > 0) {
                            const veiculo_id = result2[0].veiculo_id;
                            db.query("UPDATE veiculos SET km = ? WHERE id = ?", [kmFinalValue, veiculo_id], (err, result3) => {
                                if (err) {
                                    console.error("Erro ao atualizar km do veículo:", err);
                                } else {
                                    console.log(`Veículo ${veiculo_id} atualizado para km=${kmFinalValue} via edição.`);
                                    // Não atualiza o km_inicial para manter o valor original
                                    checkOilChangeForVehicle(veiculo_id);
                                    // Chama a verificação para manutenção automática
                                    db.query("SELECT * FROM veiculos WHERE id = ?", [veiculo_id], (err, result4) => {
                                        if (err) {
                                            console.error("Erro ao buscar veículo para manutenção:", err);
                                        } else if (result4.length > 0) {
                                            const veiculoAtualizado = result4[0];
                                            autoGenerateMaintenance(veiculoAtualizado);
                                        }
                                    });
                                }
                            });
                        }
                    });
                }
            }

            if (novasMultas.length === 0) {
                return res.redirect('/relatorio-uso');
            }

            db.query("SELECT veiculo_id FROM uso_veiculos WHERE id = ?", [id], (err, result5) => {
                if (err) {
                    console.error("Erro ao buscar veículo:", err);
                    return renderError("Erro ao buscar veículo para registrar novas multas.");
                }
                if (result5.length === 0) {
                    return renderError("Veículo não encontrado para este uso.");
                }
                const veiculo_id = result5[0].veiculo_id;
                const valores = novasMultas.map(multa => [id, veiculo_id, multa.trim()]);
                db.query("INSERT INTO multas (uso_id, veiculo_id, multa) VALUES ?", [valores], (err) => {
                    if (err) {
                        console.error("Erro ao registrar novas multas:", err);
                        return renderError("Erro ao registrar novas multas. Por favor, tente novamente.");
                    }
                    return res.redirect('/relatorio-uso');
                });
            });
        });
    }
});




// Rota pra marcar que a troca de óleo foi feita
app.post('/troca-feita/:id', isAuthenticated, isAdmin, (req, res) => {
    const { id } = req.params;
    // Atualiza a última troca com o km atual
    db.query('UPDATE veiculos SET ultimaTrocaOleo = km WHERE id = ?', [id], (err, result) => {
        if (err) {
            console.error("Erro ao atualizar troca de óleo:", err);
            return res.status(500).send("Erro ao atualizar troca de óleo.");
        }
        console.log(`Veículo ${id}: troca de óleo registrada.`);
        res.redirect('/notificacoes');
    });
});

// Rota pra excluir uma multa
app.post('/excluir-multa/:id', isAuthenticated, isAdmin, (req, res) => {
    const { id } = req.params;
    db.query("DELETE FROM multas WHERE id = ?", [id], (err, result) => {
        if (err) {
            console.error("Erro ao excluir multa:", err);
            return res.status(500).send("Erro ao excluir multa.");
        }
        res.redirect('back');
    });
});

// Rota pra excluir uso e suas multas
app.post('/excluir-uso/:id', isAuthenticated, isAdmin, (req, res) => {
    const { id } = req.params;
    db.query("DELETE FROM multas WHERE uso_id = ?", [id], (err, result) => {
        if (err) {
            console.error("Erro ao excluir multas:", err);
            return res.status(500).send("Erro ao excluir multas.");
        }
        db.query("DELETE FROM uso_veiculos WHERE id = ?", [id], (err, result) => {
            if (err) {
                console.error("Erro ao excluir uso:", err);
                return res.status(500).send("Erro ao excluir uso.");
            }
            res.redirect('/relatorio-uso');
        });
    });
});

// Rota pra excluir múltiplos usos
app.post('/excluir-multiplos-usos', isAuthenticated, isAdmin, (req, res) => {
    const { ids } = req.body;

    if (!ids || !Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ message: 'IDs inválidos.' });
    }

    db.beginTransaction(err => {
        if (err) {
            console.error('Erro ao iniciar transação:', err);
            return res.status(500).json({ message: 'Erro na transação.' });
        }

        const queryMultas = 'DELETE FROM multas WHERE uso_id IN (?)';
        db.query(queryMultas, [ids], (err, resultMultas) => {
            if (err) {
                console.error('Erro ao excluir multas:', err);
                return db.rollback(() => {
                    res.status(500).json({ message: 'Erro ao excluir multas.' });
                });
            }

            const queryUso = 'DELETE FROM uso_veiculos WHERE id IN (?)';
            db.query(queryUso, [ids], (err, resultUso) => {
                if (err) {
                    console.error('Erro ao excluir usos:', err);
                    return db.rollback(() => {
                        res.status(500).json({ message: 'Erro ao excluir usos.' });
                    });
                }

                if (resultUso.affectedRows === 0) {
                    return db.rollback(() => {
                        res.status(404).json({ message: 'Nenhum registro encontrado.' });
                    });
                }

                db.commit(err => {
                    if (err) {
                        console.error('Erro ao commitar transação:', err);
                        return db.rollback(() => {
                            res.status(500).json({ message: 'Erro ao finalizar exclusão.' });
                        });
                    }
                    res.json({ message: 'Registros excluídos com sucesso.' });
                });
            });
        });
    });
});

// Rota pra exibir a tela de edição do veículo
app.get('/editar-veiculo/:id', isAuthenticated, (req, res) => {
    const id = req.params.id;
    db.query("SELECT * FROM veiculos WHERE id = ?", [id], (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).send("Veículo não encontrado.");
        }
        res.render('editar-veiculo', {
            veiculo: results[0],
            title: 'Editar Veículo',
            layout: 'layout',
            activePage: 'editar-veiculo'
        });

    });
});

// Rota para atualizar dados do veículo
app.post('/editar-veiculo/:id', isAuthenticated, (req, res) => {
    const id = req.params.id;
    const { nome, placa, km, ultimaTrocaOleo, modelo, justificativaKm } = req.body;

    // Primeiro, obtém o km atual do veículo para comparar
    db.query(
        "SELECT km AS currentKm FROM veiculos WHERE id = ?",
        [id],
        (err, resultVehicle) => {
            if (err) {
                console.error("Erro ao buscar dados do veículo:", err);
                return res.status(500).send("Erro interno ao buscar dados do veículo.");
            }
            if (resultVehicle.length === 0) {
                return res.status(404).send("Veículo não encontrado.");
            }
            const currentKm = parseInt(resultVehicle[0].currentKm, 10);

            // Verifica se há algum uso em andamento para este veículo
            db.query(
                "SELECT COUNT(*) AS count FROM uso_veiculos WHERE veiculo_id = ? AND (km_final IS NULL OR data_hora_final IS NULL)",
                [id],
                (err, result) => {
                    if (err) {
                        console.error("Erro ao verificar uso em andamento:", err);
                        return res.status(500).send("Erro ao verificar uso em andamento.");
                    }
                    if (result[0].count > 0) {
                        // Bloqueia a atualização se houver uso em andamento
                        return res.status(400).send("Não é possível atualizar o veículo, pois há um uso em andamento.");
                    } else {
                        // Atualiza os dados do veículo
                        db.query(
                            "UPDATE veiculos SET nome = ?, placa = ?, km = ?, ultimaTrocaOleo = ?, modelo = ? WHERE id = ?",
                            [nome, placa, km, ultimaTrocaOleo, modelo, id],
                            (err) => {
                                if (err) {
                                    console.error("Erro ao atualizar veículo:", err);
                                    return res.status(500).send("Erro ao atualizar veículo.");
                                }

                                // Se a quilometragem foi alterada, insere uma notificação com a justificativa e o usuário responsável
                                // Obtém ID e e-mail do usuário autenticado
                                //const userId = req.user ? req.user.id : 'Desconhecido';
                                const userEmail = req.user ? req.user.email : 'E-mail não disponível';

                                // Primeiro, busque os detalhes do veículo no banco de dados
                                db.query(
                                    "SELECT placa, modelo FROM veiculos WHERE id = ?",
                                    [id],
                                    (err, results) => {
                                        if (err) {
                                            console.error("Erro ao buscar dados do veículo:", err);
                                            return;
                                        }

                                        if (results.length === 0) {
                                            console.warn("Veículo não encontrado no banco de dados.");
                                            return;
                                        }

                                        const { placa, modelo } = results[0];

                                        if (parseInt(km, 10) !== currentKm) {
                                            const mensagem = `Usuário (${userEmail}) alterou a quilometragem do veículo (Placa: ${placa}, Modelo: ${modelo}) de ${currentKm} para ${km}. Justificativa: ${justificativaKm || 'Sem justificativa.'}`;

                                            db.query(
                                                "INSERT INTO notificacoes (mensagem, data_hora) VALUES (?, NOW())",
                                                [mensagem],
                                                (err) => {
                                                    if (err) {
                                                        console.error("Erro ao inserir notificação de km editado:", err);
                                                    }
                                                }
                                            );
                                        }
                                    }
                                );




                                res.redirect('/');
                            }
                        );
                    }
                }
            );
        }
    );
});




// Rota pra excluir veículo
app.post('/excluir-veiculo/:id', isAuthenticated, isAdmin, (req, res) => {
    const id = req.params.id;
    db.query("DELETE FROM veiculos WHERE id = ?", [id], (err) => {
        if (err) {
            return res.status(500).send("Erro ao excluir veículo.");
        }
        res.redirect('/');
    });
});

// Rota de notificações: mostra veículos que precisam trocar óleo e notificações de alteração de quilometragem
app.get('/notificacoes', isAuthenticated, (req, res) => {
    // Query para veículos que precisam trocar óleo
    const oilQuery = `
      SELECT *, (km - ultimaTrocaOleo) AS kmDesdeUltimaTroca 
      FROM veiculos 
      WHERE (km - ultimaTrocaOleo) >= 10000
    `;
    // Query para notificações de km editado
    const notifQuery = `
      SELECT * FROM notificacoes
      ORDER BY data_hora DESC
    `;
    db.query(oilQuery, (err, oilResults) => {
        if (err) {
            console.error("Erro ao buscar notificações de óleo:", err);
            return res.status(500).send("Erro no servidor");
        }
        db.query(notifQuery, (err, notifResults) => {
            if (err) {
                console.error("Erro ao buscar notificações de km editado:", err);
                return res.status(500).send("Erro no servidor");
            }
            res.render('notificacoes', {
                oilVehicles: oilResults,
                kmNotifications: notifResults,
                title: 'Notificações',
                layout: 'layout',
                activePage: 'notificacoes'
            });
        });
    });
});

app.post('/excluir-notificacao-alteracao-km/:id', isAuthenticated, isAdmin, async (req, res) => {
    const { id } = req.params;
    db.query('DELETE FROM notificacoes WHERE id = ?', [id], (err, results) => {
        if (err) {
            console.error('Erro ao excluir notificação:', err);
            return res.status(500).send('Erro ao excluir notificação.');
        }
        // Após a exclusão, redireciona para a página de notificações
        res.redirect('/notificacoes');
    });
});
const moment = require('moment');

// Função para validar CPF
function validarCPF(cpf) {
    // Remove pontos e traços
    cpf = cpf.replace(/[^\d]+/g, '');
    if (cpf.length !== 11 || /^(\d)\1+$/.test(cpf)) {
        return false;
    }
    let soma = 0, resto;
    for (let i = 1; i <= 9; i++) {
        soma += parseInt(cpf.substring(i - 1, i)) * (11 - i);
    }
    resto = (soma * 10) % 11;
    if (resto === 10 || resto === 11) {
        resto = 0;
    }
    if (resto !== parseInt(cpf.substring(9, 10))) {
        return false;
    }
    soma = 0;
    for (let i = 1; i <= 10; i++) {
        soma += parseInt(cpf.substring(i - 1, i)) * (12 - i);
    }
    resto = (soma * 10) % 11;
    if (resto === 10 || resto === 11) {
        resto = 0;
    }
    if (resto !== parseInt(cpf.substring(10, 11))) {
        return false;
    }
    return true;
}

app.get('/registro-motorista', isAuthenticated, (req, res) => {
    const email = req.user.email;

    // Consulta para verificar se o motorista já possui cadastro
    db.query('SELECT id FROM motoristas WHERE email = ?', [email], (err, results) => {
        if (err) {
            console.error('Erro ao verificar cadastro do motorista:', err);
            return res.status(500).send('Erro no servidor.');
        }

        // Se já existir cadastro, renderiza o formulário com uma mensagem de erro
        if (results.length > 0) {
            return res.render('registro-motorista', {
                activePage: 'motorista',
                user: req.user,
                errorMessage: 'Cadastro já realizado. Você já possui um motorista cadastrado.'
            });
        }

        // Se não houver cadastro, renderiza o formulário de registro normalmente
        res.render('registro-motorista', { activePage: 'motorista', user: req.user });
    });
});





// Rota para cadastro de motoristas
app.post('/api/cadastro-motorista', isAuthenticated, upload.single('foto'), async (req, res) => {
    //console.log('Dados do corpo:', req.body);
    //console.log('Dados do arquivo:', req.file);

    const { nome, cpf, cnh, dataValidade, categoria } = req.body;
    const foto = req.file ? req.file.filename : null;

    // O email vem do usuário autenticado (tabela "usuarios")
    const email = req.user.email;

    // Validação da data de validade da CNH
    if (moment(dataValidade).isBefore(moment(), 'day')) {
        return res.status(400).json({ success: false, message: 'CNH vencida. Cadastro não permitido.' });
    }

    // Validação do CPF
    if (!validarCPF(cpf)) {
        return res.status(400).json({ success: false, message: 'CPF inválido.' });
    }

    // Verifica se o CPF já está cadastrado
    db.query('SELECT id FROM motoristas WHERE cpf = ?', [cpf], (err, results) => {
        if (err) {
            console.error('Erro ao verificar CPF:', err);
            return res.status(500).json({ success: false, message: 'Erro ao verificar CPF.' });
        }

        if (results.length > 0) {
            return res.status(400).json({ success: false, message: 'CPF já cadastrado.' });
        }

        // Se o CPF não existe, insere o novo motorista, incluindo o campo email
        const query = `
        INSERT INTO motoristas (nome, email, cpf, cnh, data_validade, categoria, foto)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `;
        const values = [nome, email, cpf, cnh, dataValidade, categoria, foto];

        db.query(query, values, (err, results) => {
            if (err) {
                console.error('Erro ao cadastrar motorista:', err);
                return res.status(500).json({ success: false, message: 'Erro ao cadastrar motorista.' });
            }
            return res.status(200).json({ success: true, message: 'Motorista cadastrado com sucesso!' });
        });
    });
});

//  Manutenções adicionais (rodízio de pneus, troca de pneus, pastilhas e discos de freio) //

// Função para enviar notificação de manutenção (por email e via Socket.IO)
function sendMaintenanceNotification(veiculo, manutencao) {
    const transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });
    const mailOptions = {
        to: process.env.NOTIFY_EMAIL || process.env.EMAIL_USER,
        from: process.env.EMAIL_USER,
        subject: `Manutenção Pendente (${manutencao.tipo}): ${veiculo.nome} - ${veiculo.placa}`,
        text: `O veículo ${veiculo.nome} (Placa: ${veiculo.placa}) necessita de ${manutencao.tipo}. ` +
            `Detalhes: ${manutencao.descricao || 'Sem descrição.'}`
    };
    transporter.sendMail(mailOptions, (err, info) => {
        if (err) console.error("Erro ao enviar email de manutenção:", err);
        else console.log("Email de manutenção enviado:", info.response);
    });
    io.emit('maintenanceNotification', { veiculo, manutencao });
}

// Função para checar manutenções pendentes para um veículo
function checkMaintenanceForVehicle(veiculo_id) {
    const queryVeiculo = `SELECT * FROM veiculos WHERE id = ?`;
    db.query(queryVeiculo, [veiculo_id], (err, results) => {
        if (err) {
            console.error("Erro ao buscar veículo para manutenção:", err);
            return;
        }
        if (results.length > 0) {
            const veiculo = results[0];
            // Busca manutenções pendentes para este veículo
            const queryManutencoes = `
                SELECT * FROM manutencoes 
                WHERE veiculo_id = ? AND status = 'pendente'
            `;
            db.query(queryManutencoes, [veiculo_id], (err, manutencoes) => {
                if (err) {
                    console.error("Erro ao buscar manutenções:", err);
                    return;
                }
                const hoje = new Date();
                manutencoes.forEach(manutencao => {
                    let precisaNotificar = false;
                    // Se tiver km agendado e a quilometragem atual for maior ou igual
                    if (manutencao.km_agendado && Number(veiculo.km) >= Number(manutencao.km_agendado)) {
                        precisaNotificar = true;
                    }
                    // Se tiver data agendada e hoje for igual ou depois
                    if (manutencao.data_agendada && hoje >= new Date(manutencao.data_agendada)) {
                        precisaNotificar = true;
                    }
                    if (precisaNotificar) {
                        console.log(`Manutenção pendente detectada: ${manutencao.tipo} para veículo ${veiculo.placa}`);
                        sendMaintenanceNotification(veiculo, manutencao);
                    }
                });
            });
        }
    });
}

/* Rotas para manutenção */

// Rota para exibir formulário de cadastro de manutenção para um veículo
app.get('/registrar-manutencao/:veiculo_id', isAuthenticated, isAdmin, (req, res) => {
    const { veiculo_id } = req.params;
    db.query("SELECT * FROM veiculos WHERE id = ?", [veiculo_id], (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).send("Veículo não encontrado.");
        }
        const veiculo = results[0];
        res.render('registrar-manutencao', {
            title: 'Registrar Manutenção',
            layout: 'layout',
            activePage: 'manutencao',
            veiculo,
            tipos: ['Rodízio de Pneus', 'Troca de Pneus', 'Troca de Pastilhas', 'Troca de Discos de Freio']
        });
    });
});

// Rota para processar cadastro de manutenção
app.post('/registrar-manutencao/:veiculo_id', isAuthenticated, isAdmin, (req, res) => {
    const { veiculo_id } = req.params;
    const { tipo, descricao, km_agendado, data_agendada } = req.body;
    const query = `
        INSERT INTO manutencoes (veiculo_id, tipo, descricao, km_agendado, data_agendada)
        VALUES (?, ?, ?, ?, ?)
    `;
    db.query(query, [veiculo_id, tipo, descricao, km_agendado || null, data_agendada || null], (err, result) => {
        if (err) {
            console.error("Erro ao registrar manutenção:", err);
            return res.status(500).send("Erro ao registrar manutenção.");
        }
        res.redirect('/manutencoes');
    });
});

// Rota para listar todas as manutenções (de todos os veículos)
app.get('/manutencoes', isAuthenticated, isAdmin, (req, res) => {
    const query = `
      SELECT m.*, v.placa, v.nome as veiculo_nome 
      FROM manutencoes m
      JOIN veiculos v ON m.veiculo_id = v.id
      ORDER BY m.status, m.data_agendada
    `;
    db.query(query, (err, results) => {
        if (err) {
            console.error("Erro ao buscar manutenções:", err);
            return res.status(500).send("Erro ao buscar manutenções.");
        }
        res.render('manutencoes', {
            title: 'Manutenções',
            layout: 'layout',
            activePage: 'manutencoes',
            manutencoes: results
        });
    });
});

// Rota para marcar uma manutenção como realizada
app.post('/manutencoes/realizada/:id', isAuthenticated, isAdmin, (req, res) => {
    const { id } = req.params;
    const updateQuery = `
      UPDATE manutencoes 
      SET status = 'realizada', data_realizada = CURDATE() 
      WHERE id = ?
    `;
    db.query(updateQuery, [id], (err, result) => {
        if (err) {
            console.error("Erro ao atualizar manutenção:", err);
            return res.status(500).send("Erro ao atualizar manutenção.");
        }
        res.redirect('/manutencoes');
    });
});

/* Fim das funcionalidades de manutenção */

// Rota para cadastro de novo reembolso
app.post('/reembolsos', upload.single('comprovante'), async (req, res) => {
    try {
        const { motorista_id, valor } = req.body;
        // Se um arquivo foi enviado, obtenha o caminho
        const comprovante = req.file ? req.file.filename : null;

        await query(
            'INSERT INTO reembolsos (motorista_id, valor, comprovante) VALUES (?, ?, ?)',
            [motorista_id, valor, comprovante]
        );

        res.redirect('/reembolsos');
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao cadastrar reembolso');
    }
});
// Rota para exibir o formulário, a lista de reembolsos e os dados para o gráfico
app.get('/reembolsos', async (req, res) => {
    try {
        // Consulta para buscar os reembolsos cadastrados com os dados do motorista
        const reembolsos = await query(`
        SELECT r.*, m.nome as motorista_nome 
        FROM reembolsos r 
        JOIN motoristas m ON r.motorista_id = m.id 
        ORDER BY r.criado_em ASC
      `);

        // Consulta para buscar motoristas para o formulário
        const motoristas = await query('SELECT id, nome FROM motoristas');

        // Envie os dados completos dos reembolsos para a tabela e para o gráfico
        res.render('reembolsos', {
            reembolsos,
            motoristas,
            reembolsosGrafico: reembolsos, // mesma lista, utilizada também para o gráfico
            title: 'Gerenciar Reembolsos',
            activePage: 'reembolsos'
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro no servidor');
    }
});

app.get('/relatorio-consumo', isAuthenticated, async (req, res) => {
    try {
        // Fator de consumo: eficiência média em km por litro
        const eficiencia = 10; // km por litro 
        // Preço da gasolina
        const precoGasolina = 6.45;

        // Consulta para buscar os registros de uso com o cálculo da distância, consumo estimado e custo
        const consumoResult = await query(
            `
        SELECT 
          uso.id, 
          veiculos.placa, 
          uso.motorista, 
          uso.km_inicial, 
          uso.km_final, 
          (uso.km_final - uso.km_inicial) AS distancia,
          ROUND((uso.km_final - uso.km_inicial) / ?, 2) AS consumo_estimado,
          ROUND(((uso.km_final - uso.km_inicial) / ?) * ?, 2) AS custo_estimado
        FROM uso_veiculos AS uso
        JOIN veiculos ON uso.veiculo_id = veiculos.id
        WHERE uso.km_final IS NOT NULL
        ORDER BY uso.data_criacao DESC
        `,
            [eficiencia, eficiencia, precoGasolina]
        );

        res.render('relatorioConsumo', {
            title: 'Relatório de Consumo Estimado',
            layout: 'layout',
            activePage: 'relatorioConsumo',
            consumoResult
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro no servidor ao gerar relatório de consumo.');
    }
});



// Socket.IO: conexão com o cliente
io.on("connection", (socket) => {
    console.log("Cliente conectado via Socket.IO.");
});

// GPS - Configura CORS e rota pra atualizar localização
const cors = require('cors');
app.use(cors({
    origin: ['https://rococo-kangaroo-21ce36.netlify.app', 'http://localhost:3000', 'http://127.0.0.1:5500']
}));

app.post('/update-location', (req, res) => {
    const { vehicleId, latitude, longitude } = req.body;
    console.log(`Veículo ${vehicleId}: Latitude ${latitude}, Longitude ${longitude}`);
    // Emite o evento 'locationUpdate' para todos os clientes conectados
    io.emit('locationUpdate', { vehicleId, latitude, longitude });
    res.json({ status: 'ok', received: req.body });
});


// Rotas pra servir o manifest e o service worker (PWA)
//app.get('/manifest.json', (req, res) => {
//res.sendFile(path.join(__dirname, 'public', 'manifest.json'));
//});

//app.get('/service-worker.js', (req, res) => {
// res.sendFile(path.join(__dirname, 'public', 'service-worker.js'));
//});

/* //Código de registro do service worker (lembre: isso roda no browser!)
if ('serviceWorker' in navigator) {
   window.addEventListener('load', () => {
     navigator.serviceWorker.register('/service-worker.js')
       .then(registration => {
         console.log('Service Worker registrado com sucesso:', registration.scope);
       })
       .catch(error => {
         console.error('Falha ao registrar o Service Worker:', error);
       });
   });
} */

/*
// Código para iniciar o servidor com Socket.IO (opcional)
// server.listen(port, () => {
//     console.log(`Servidor rodando na porta ${port}`);
// });
*/
