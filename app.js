require('dotenv').config();
const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const mysql = require('mysql2');
//const mysql = require('mysql2/promise');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const session = require('express-session');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

//time zone
process.env.TZ = 'America/Sao_Paulo';
// servidor HTTP  , Socket.IO
const https = require('https');

const app = express();

let server;

const HTTPS_ENABLED = process.env.HTTPS_ENABLED === 'true';

if (HTTPS_ENABLED) {
  const sslKeyPath = process.env.SSL_KEY_PATH || '/certs/privkey.pem';
  const sslCertPath = process.env.SSL_CERT_PATH || '/certs/fullchain.pem';

  const privateKey = fs.readFileSync(sslKeyPath, 'utf8');
  const certificate = fs.readFileSync(sslCertPath, 'utf8');

  const credentials = { key: privateKey, cert: certificate };

  const https = require('https');
  server = https.createServer(credentials, app);

  console.log("Servidor HTTPS configurado.");
} else {
  const http = require('http');
  server = http.createServer(app);

  console.log("Servidor HTTP configurado.");
}

const { Server } = require('socket.io');

const TRUSTED_ORIGINS = ["http://localhost:3000"];
const io = new Server(server, {
    cors: {
        origin: (origin, callback) => {
            if (!origin || TRUSTED_ORIGINS.includes(origin)) {
                return callback(null, true);
            }
            callback(new Error("Origem não permitida"));
        },
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


// compatibilidade nas requisições
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
        const ext = path.extname(file.originalname).toLowerCase();
        if (['.png', '.jpg', '.jpeg', '.gif'].includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error('Apenas imagens PNG/JPG/GIF são permitidas'), false);
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

//app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
const helmet = require('helmet');
//const crypto = require('crypto');

app.use((req, res, next) => {
    res.locals.nonce = crypto.randomBytes(16).toString('base64');
    next();
});



app.use(
    helmet({

        contentSecurityPolicy: false,

        crossOriginEmbedderPolicy: false
    })
);

/*
app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
  
          // Scripts de Bootstrap, jQuery, DataTables, Leaflet, Socket.IO…
          scriptSrc: [
            "'self'",
            "'unsafe-inline'",
            'https://cdn.jsdelivr.net',
            'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js',
            'https://cdn.datatables.net',
            'https://code.jquery.com',
            'https://maps.googleapis.com',
            'https://maps.gstatic.com',
            'https://unpkg.com',
            'https://cdn.socket.io'
          ],
  
          // Estilos de Bootstrap, DataTables, Google Fonts, Leaflet…
          styleSrc: [
            "'self'",
            "'unsafe-inline'",
            'https://cdn.jsdelivr.net',
            'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css',
            'https://cdn.datatables.net',
            'https://fonts.googleapis.com',
            'https://maps.googleapis.com',
            'https://unpkg.com'
          ],
  
          // Imagens: placeholders, tiles do OSM, logos e ícones
          imgSrc: [
            "'self'",
            'data:',
            'blob:',
            'https://via.placeholder.com',
            'https://maps.googleapis.com',
            'https://maps.gstatic.com',
            'https://www.inova.in',
            'https://cdn-icons-png.flaticon.com',
            'https://*.tile.openstreetmap.org'
          ],
  
          // XHR / WebSocket (socket.io no mesmo host e possíveis tiles por XHR)
          connectSrc: [
            "'self'",
            'https://maps.googleapis.com',
            'https://maps.gstatic.com',
            'wss://' + process.env.HOSTNAME,
            'https://cdn.socket.io'
          ],
  
          frameSrc: [
            "'self'",
            'https://www.google.com',
            'https://maps.googleapis.com'
          ],
  
          objectSrc: ["'none'"],
          frameAncestors: ["'self'"]
        }
      },
      crossOriginEmbedderPolicy: false
    })
  );
  */



  const isProduction = process.env.NODE_ENV === 'production';
 
  
  app.use(session({
    secret: process.env.SECRET_SESSION,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 30 * 60 * 1000, // 30 minutos
      secure: HTTPS_ENABLED, // Se HTTPS, cookie só via HTTPS
      httpOnly: true,
      sameSite: HTTPS_ENABLED ? 'none' : 'lax'
    }
  }));
  


// sanitização global POST
app.use((req, res, next) => {
    if (req.method === 'POST') {
        Object.keys(req.body).forEach(field => {
            const val = req.body[field];
            if (typeof val === 'string') {
                // escapa <, >, &, ', " e / para evitar XSS
                req.body[field] = validator.escape(val);
            }
        });
    }
    next();
});
// Rate limiting
const rateLimit = require('express-rate-limit');
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 min
    max: 10,                  // até 10 tentativas
    message: "Muitas tentativas, aguarde 15 minutos."
});

app.use('/login', authLimiter);
app.use('/forgot-password', authLimiter);


// Body-parsers e sanitização
const { body, validationResult } = require('express-validator');
const validator = require('validator');


//app.use(multer().none());
// CSRF
const csurf = require('csurf');
const csrfProtection = csurf();
//app.use(csrfProtection);
/* Em todas as views, expor req.csrfToken()
app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    next();
});
*/


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
// so user autenticado acesso /uploads
app.use(
    '/uploads',
    isAuthenticated,  // só quem estiver logado cai aqui
    express.static(path.join(__dirname, 'uploads'))
);

// GET /login — gera e envia o token para a view
app.get('/login',
    csrfProtection,
    (req, res) => {
        res.render('login', {
            layout: 'login',
            csrfToken: req.csrfToken()    // passa o token aqui
        });
    }
);


// POST /login — valida o token depois do body-parser e do rate limiter
app.post('/login',
    authLimiter,
    express.urlencoded({ extended: true }), // garante que req.body._csrf exista
    csrfProtection,                         //  valida o token
    [
        body('email').isEmail().normalizeEmail(),
        body('password').isLength({ min: 8 })
    ],
    (req, res, next) => {
        passport.authenticate('local', (err, user, info) => {
            if (err) return next(err);
            if (!user) return res.redirect('/login');
            req.session.regenerate((err) => {
                if (err) return next(err);
                req.logIn(user, (err) => {
                    if (err) return next(err);
                    return res.redirect('/');
                });
            });
        })(req, res, next);
    }
);


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
        else console.log("Email troca de oleo enviado:", info.response);
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
           // console.log(`Checando veículo ${veiculo.id}: km=${km}, última troca=${ultimaTroca}, diff=${km - ultimaTroca}`);
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


app.use((req, res, next) => {
    //  `user` fique disponível em todas as views EJS
    res.locals.user = req.user;
    next();
});
app.use(passport.initialize());
app.use(passport.session());

//const util = require('util');
//const query = util.promisify(db.query).bind(db);

app.get('/', isAuthenticated, csrfProtection, async (req, res) => {
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

        // Relatório: Tempo de Uso por Dia
        const tempoUsoDiaResult = await query(`
          SELECT 
            DATE(data_hora_inicial) AS dia, 
            SEC_TO_TIME(SUM(TIMESTAMPDIFF(SECOND, data_hora_inicial, data_hora_final))) AS totalTempoUsoDia
          FROM uso_veiculos
          GROUP BY DATE(data_hora_inicial)
          ORDER BY dia DESC
        `);

        // Relatório: Tempo de Uso por Mês
        const tempoUsoMesResult = await query(`
          SELECT 
            DATE_FORMAT(data_hora_inicial, '%Y-%m') AS mes, 
            SEC_TO_TIME(SUM(TIMESTAMPDIFF(SECOND, data_hora_inicial, data_hora_final))) AS totalTempoUsoMes
          FROM uso_veiculos
          GROUP BY DATE_FORMAT(data_hora_inicial, '%Y-%m')
          ORDER BY mes DESC
        `);

        // Relatório: Tempo de Uso por Ano
        const tempoUsoAnoResult = await query(`
          SELECT 
            YEAR(data_hora_inicial) AS ano, 
            SEC_TO_TIME(SUM(TIMESTAMPDIFF(SECOND, data_hora_inicial, data_hora_final))) AS totalTempoUsoAno
          FROM uso_veiculos
          GROUP BY YEAR(data_hora_inicial)
          ORDER BY ano DESC
        `);

        // Relatório: Tempo de Uso por Motorista
        const tempoUsoMotoristaResult = await query(`
          SELECT 
            motorista, 
            SEC_TO_TIME(SUM(TIMESTAMPDIFF(SECOND, data_hora_inicial, data_hora_final))) AS totalTempoUsoMotorista
          FROM uso_veiculos
          GROUP BY motorista
          ORDER BY totalTempoUsoMotorista DESC
        `);

        // Manutenções pendentes
        const manutencoesPendentes = await query(`
          SELECT m.*, v.placa, v.nome as veiculo_nome 
          FROM manutencoes m
          JOIN veiculos v ON m.veiculo_id = v.id
          WHERE m.status = 'pendente'
          ORDER BY m.data_agendada ASC
        `);

        // Estatísticas de viagens utilizando a tabela uso_veiculos e a coluna "finalidade"
        // Agrupamento por Dia
        const viagensTrabalhoDiaResult = await query(`
          SELECT DATE(data_criacao) AS dia, COUNT(*) AS totalViagensTrabalho
          FROM uso_veiculos
          WHERE finalidade = 'trabalho'
          GROUP BY DATE(data_criacao)
          ORDER BY dia DESC
        `);
        const viagensPessoalDiaResult = await query(`
          SELECT DATE(data_criacao) AS dia, COUNT(*) AS totalViagensPessoal
          FROM uso_veiculos
          WHERE finalidade = 'pessoal'
          GROUP BY DATE(data_criacao)
          ORDER BY dia DESC
        `);

        // Agrupamento por Mês
        const viagensTrabalhoMesResult = await query(`
          SELECT DATE_FORMAT(data_criacao, '%Y-%m') AS mes, COUNT(*) AS totalViagensTrabalho
          FROM uso_veiculos
          WHERE finalidade = 'trabalho'
          GROUP BY DATE_FORMAT(data_criacao, '%Y-%m')
          ORDER BY mes DESC
        `);
        const viagensPessoalMesResult = await query(`
          SELECT DATE_FORMAT(data_criacao, '%Y-%m') AS mes, COUNT(*) AS totalViagensPessoal
          FROM uso_veiculos
          WHERE finalidade = 'pessoal'
          GROUP BY DATE_FORMAT(data_criacao, '%Y-%m')
          ORDER BY mes DESC
        `);

        // Agrupamento por Ano
        const viagensTrabalhoAnoResult = await query(`
          SELECT YEAR(data_criacao) AS ano, COUNT(*) AS totalViagensTrabalho
          FROM uso_veiculos
          WHERE finalidade = 'trabalho'
          GROUP BY YEAR(data_criacao)
          ORDER BY ano DESC
        `);
        const viagensPessoalAnoResult = await query(`
          SELECT YEAR(data_criacao) AS ano, COUNT(*) AS totalViagensPessoal
          FROM uso_veiculos
          WHERE finalidade = 'pessoal'
          GROUP BY YEAR(data_criacao)
          ORDER BY ano DESC
        `);

        // Estatísticas de viagens por motorista, agrupando por finalidade
        const viagensMotoristaResult = await query(`
          SELECT motorista, finalidade, COUNT(*) AS totalViagens
          FROM uso_veiculos
          WHERE finalidade IN ('trabalho', 'pessoal')
          GROUP BY motorista, finalidade
          ORDER BY motorista, totalViagens DESC
        `);



        // KM Rodados por motorista (top 10)
        const kmMotoristaResult = await query(`
    SELECT 
      motorista, 
      SUM(km_final - km_inicial) AS totalKm
    FROM uso_veiculos
    GROUP BY motorista
    ORDER BY totalKm DESC
    LIMIT 10
  `);

        // KM Rodados por viagem (últimas 10 viagens)
        const kmViagemResult = await query(`
    SELECT 
      id AS viagemId, 
      (km_final - km_inicial) AS kmViagem
    FROM uso_veiculos
    ORDER BY data_criacao DESC
    LIMIT 10
  `);

        // KM Rodados por dia (últimos 7 dias)
        const kmDiaResult = await query(`
    SELECT 
      DATE(data_criacao) AS dia, 
      SUM(km_final - km_inicial) AS totalKmDia
    FROM uso_veiculos
    WHERE data_criacao >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
    GROUP BY DATE(data_criacao)
    ORDER BY dia DESC
  `);

        // KM Rodados por mês (últimos 6 meses)
        const kmMesResult = await query(`
    SELECT 
      DATE_FORMAT(data_criacao, '%Y-%m') AS mes, 
      SUM(km_final - km_inicial) AS totalKmMes
    FROM uso_veiculos
    WHERE data_criacao >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)
    GROUP BY DATE_FORMAT(data_criacao, '%Y-%m')
    ORDER BY mes DESC
  `);

        // KM Rodados por ano (últimos 5 anos)
        const kmAnoResult = await query(`
    SELECT 
      YEAR(data_criacao) AS ano, 
      SUM(km_final - km_inicial) AS totalKmAno
    FROM uso_veiculos
    WHERE data_criacao >= DATE_SUB(CURDATE(), INTERVAL 5 YEAR)
    GROUP BY YEAR(data_criacao)
    ORDER BY ano DESC
  `);




        res.render('dashboard', {
            title: 'Dashboard',
            csrfToken: req.csrfToken(),
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
            tempoUsoDia: tempoUsoDiaResult,             // Estatística: tempo de uso por dia
            tempoUsoMes: tempoUsoMesResult,             // Estatística: tempo de uso por mês
            tempoUsoAno: tempoUsoAnoResult,             // Estatística: tempo de uso por ano
            tempoUsoMotorista: tempoUsoMotoristaResult, // Estatística: tempo de uso por motorista
            manutencoesPendentes,   // Dados das manutenções pendentes
            // Estatísticas de viagens (usando uso_veiculos e coluna "finalidade")
            viagensTrabalhoDia: viagensTrabalhoDiaResult,
            viagensPessoalDia: viagensPessoalDiaResult,
            viagensTrabalhoMes: viagensTrabalhoMesResult,
            viagensPessoalMes: viagensPessoalMesResult,
            viagensTrabalhoAno: viagensTrabalhoAnoResult,
            viagensPessoalAno: viagensPessoalAnoResult,
            viagensMotorista: viagensMotoristaResult,
            kmMotorista: kmMotoristaResult,
            kmViagem: kmViagemResult,
            kmDia: kmDiaResult,
            kmMes: kmMesResult,
            kmAno: kmAnoResult,

        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro no servidor');
    }
});



// Tela de esqueci minha senha
app.get('/forgot-password', csrfProtection, (req, res) => {
    res.render('forgot-password', { layout: 'forgot-password', csrfToken: req.csrfToken() });
});
app.post('/forgot-password', authLimiter, csrfProtection, (req, res) => {
    const email = validator.normalizeEmail(req.body.email || '');
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
app.get('/reset-password/:token', csrfProtection, (req, res) => {
    const { token } = req.params;
    db.query("SELECT * FROM usuarios WHERE password_reset_token = ? AND password_reset_expires > ?", [token, Date.now()], (err, results) => {
        if (err) return res.status(500).send("Erro no servidor.");
        if (results.length === 0) return res.status(400).send("Token inválido ou expirado.");
        res.render('reset-password', { layout: 'reset-password', token, csrfToken: req.csrfToken() });
    });
});

// Função para checar a força da senha
function validatePasswordStrength(password) {
    // A senha deve ter no mínimo 8 caracteres, ao menos uma letra minúscula, uma maiúscula, um dígito e um caractere especial.
    const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#()\-_=+{}[\]|;:'",.<>\/?])[A-Za-z\d@$!%*?&#()\-_=+{}[\]|;:'",.<>\/?]{8,}$/;
    return regex.test(password);
}

app.post('/reset-password/:token', csrfProtection, (req, res) => {
    const { token } = req.params;
    const { password } = req.body;
    if (!password) return res.status(400).send("Senha é obrigatória.");

    // Checagem de senha forte
    if (!validatePasswordStrength(password)) {
        return res.status(400).send("A senha deve ter pelo menos 8 caracteres, incluindo uma letra maiúscula, uma letra minúscula, um número e um caractere especial.");
    }

    db.query("SELECT * FROM usuarios WHERE password_reset_token = ? AND password_reset_expires > ?", [token, Date.now()], (err, results) => {
        if (err) return res.status(500).send("Erro no servidor.");
        if (results.length === 0) return res.status(400).send("Token inválido ou expirado.");
        const user = results[0];

        bcrypt.hash(password, 10, (err, hash) => {
            if (err) return res.status(500).send("Erro ao atualizar senha.");
            db.query("UPDATE usuarios SET senha = ?, password_reset_token = NULL, password_reset_expires = NULL WHERE id = ?", [hash, user.id], (err, result) => {
                if (err) return res.status(500).send("Erro ao atualizar senha.");
                res.send(`
                    <!DOCTYPE html>
                    <html lang="pt-br">
                    <head>
                      <meta charset="UTF-8">
                      <title>Senha Atualizada</title>
                      <script>
                        setTimeout(function() {
                          window.location.href = '/login';
                        }, 3000); // Redireciona após 3 segundos
                      </script>
                    </head>
                    <body style="background-color: #222; color: #fff; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0;">
                      <div>
                        <h1>Senha atualizada! Já pode fazer login.</h1>
                        <p>Você será redirecionado para a página de login em instantes.</p>
                      </div>
                    </body>
                    </html>
                  `);

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

app.get('/relatorio-uso', isAuthenticated, csrfProtection, async (req, res) => {
    try {
        let usoData;
        if (req.user.role === 'user') {
            // Para usuários com role "user", filtra os registros pelo email ou outro identificador
            usoData = await query(
                'SELECT * FROM uso_veiculos WHERE motorista = ? ORDER BY data_criacao DESC',
                [req.user.email]
            );
        } else {
            // Para administradores, traz todos os registros
            usoData = await query(
                'SELECT * FROM uso_veiculos ORDER BY data_criacao DESC'
            );
        }

        res.render('relatorio_uso', {
            title: 'Relatório de uso de veículos',
            csrfToken: req.csrfToken(),
            layout: 'layout',
            activePage: 'relatorio_uso',
            user: req.user,
            usoData: usoData
        });
    } catch (err) {
        console.error('Erro ao buscar registros de uso:', err);
        res.status(500).send('Erro no servidor ao obter relatório de uso.');
    }
});

app.get('/api/relatorio-uso', isAuthenticated, csrfProtection, (req, res) => {
    // Parâmetros do DataTables
    let draw = req.query.draw || 0;
    let start = parseInt(req.query.start) || 0;
    let length = parseInt(req.query.length) || 10;
    let searchValue = req.query.search ? req.query.search.value : '';

    // Mapeamento dos índices para as colunas ordenáveis (conforme ordem visual)
    let columns = [
        null,
        'veiculos.placa',
        'uso_veiculos.motorista',
        'uso_veiculos.km_inicial',
        'uso_veiculos.km_final',
        'uso_veiculos.finalidade', // novo campo
        'uso_veiculos.descricao',  // novo campo
        'data_hora_inicial',
        'data_hora_final',
        'data_criacao'
    ];

    // Parâmetros para ordenação
    let orderColumnIndex = 1; // padrão
    let orderDir = 'asc'; // padrão
    if (req.query.order && req.query.order[0]) {
        orderColumnIndex = parseInt(req.query.order[0].column);
        orderDir = req.query.order[0].dir || 'asc';
    }
    if (orderColumnIndex < 1 || orderColumnIndex > 9) {
        orderColumnIndex = 7; // padrão: data_hora_inicial
    }
    let orderColumn = columns[orderColumnIndex] || 'data_hora_inicial';

    // Constrói a cláusula WHERE base:
    // Se o usuário for "user", restringe os registros ao email do motorista (ou outro identificador)
    let whereClause = '';
    let params = [];
    if (req.user.role === 'user') {
        whereClause = 'WHERE uso_veiculos.motorista = ?';
        params.push(req.user.email);
    }

    // Se existir termo de busca, adiciona à cláusula WHERE utilizando AND se já houver filtro
    if (searchValue) {
        const searchCondition = ` (veiculos.placa LIKE ? OR uso_veiculos.motorista LIKE ? OR uso_veiculos.km_inicial LIKE ? OR uso_veiculos.km_final LIKE ? OR uso_veiculos.finalidade LIKE ? OR uso_veiculos.descricao LIKE ? OR uso_veiculos.id LIKE ?)`;
        if (whereClause) {
            whereClause += ' AND' + searchCondition;
        } else {
            whereClause = 'WHERE' + searchCondition;
        }
        const searchParam = '%' + searchValue + '%';
        // Adiciona os parâmetros de busca (7 vezes)
        params.push(searchParam, searchParam, searchParam, searchParam, searchParam, searchParam, searchParam);
    }

    // Consulta principal (com joins e agrupamento)
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

    db.query(sql, params, (err, results) => {
        if (err) {
            console.error("Erro na consulta principal:", err);
            return res.status(500).json({ error: "Erro na consulta principal" });
        }

        // Consulta para a contagem dos registros filtrados
        let countSql = `
         SELECT COUNT(DISTINCT uso_veiculos.id) AS total 
         FROM uso_veiculos
         JOIN veiculos ON uso_veiculos.veiculo_id = veiculos.id
         LEFT JOIN multas ON uso_veiculos.id = multas.uso_id
         ${whereClause}
       `;
        // Os parâmetros para contagem são os mesmos que os usados para a condição WHERE
        let countParams = [];
        if (req.user.role === 'user') {
            countParams.push(req.user.email);
        }
        if (searchValue) {
            const searchParam = '%' + searchValue + '%';
            countParams.push(searchParam, searchParam, searchParam, searchParam, searchParam, searchParam, searchParam);
        }

        db.query(countSql, countParams, (err, countResult) => {
            if (err) {
                console.error("Erro na consulta de contagem filtrada:", err);
                return res.status(500).json({ error: "Erro na consulta de contagem filtrada" });
            }
            let totalRecords = countResult[0].total;

            // Consulta para o total de registros sem filtro:

            let totalSql = '';
            let totalParams = [];
            if (req.user.role === 'user') {
                totalSql = 'SELECT COUNT(*) AS total FROM uso_veiculos WHERE motorista = ?';
                totalParams.push(req.user.email);
            } else {
                totalSql = 'SELECT COUNT(*) AS total FROM uso_veiculos';
            }
            db.query(totalSql, totalParams, (err, totalResult) => {
                if (err) {
                    console.error("Erro na consulta de contagem total:", err);
                    return res.status(500).json({ error: "Erro na consulta de contagem total" });
                }
                let totalRecordsUnfiltered = totalResult[0].total;
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





app.get(
    '/registrar-veiculo',
    isAuthenticated,
    isAdmin,
    csrfProtection,
    (req, res) => {
        res.render('registrar-veiculo', {
            title: 'Registrar veículo',
            user: req.user,
            csrfToken: req.csrfToken(),
            layout: 'layout',
            activePage: 'registrar-veiculo',

            errors: [],        // sem erros inicialmente
            errorFields: [],   // nenhum campo marcado como inválido
            data: {}           // nenhum valor pré-preenchido
        });
    }
);

app.post('/registrar-veiculo', isAuthenticated, isAdmin, csrfProtection, (req, res) => {
    const { nome, placa, km, ultimaTrocaOleo, emUsoPor, modelo, ano, cor } = req.body;
    if (!nome || !placa || !km || !ultimaTrocaOleo || !modelo || !ano || !cor) {
        return res.status(400).send('Todos os campos são obrigatórios');
    }
    db.query(
        'INSERT INTO veiculos (nome, placa, km, ultimaTrocaOleo, emUsoPor, modelo, ano, cor) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [nome, placa, km, ultimaTrocaOleo, emUsoPor, modelo, ano, cor],
        (err, result) => {
            if (err) {
                console.error('Erro ao registrar veículo:', err);
                return res.status(500).send('Erro ao registrar veículo');
            }
            res.redirect('/');
        }
    );
});

app.post('/multar/:uso_id', isAuthenticated, csrfProtection, (req, res) => {
    const { uso_id } = req.params;
    const multa = validator.escape(req.body.multa || '');

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
app.get('/registrar-multa/:veiculo_id', isAuthenticated, csrfProtection, (req, res) => {
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
            csrfToken: req.csrfToken(),
            mensagemErro: null,
            title: 'Registro de Multa',
            layout: 'layout',
            activePage: 'registrarMulta',
            user: req.user
        });
    });
});


app.post('/registrar-multa/:veiculo_id',
    isAuthenticated,
    isAdmin,
    csrfProtection,
    (req, res) => {
        const { veiculo_id } = req.params;
        const { data_multa, multa } = req.body;

        if (!data_multa || !multa) {
            return res.status(400).send("Campos obrigatórios não preenchidos.");
        }

        const dataMulta = new Date(data_multa);
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

            let uso_id = usoResult.length > 0 ? usoResult[0].id : null;

            // Se não encontrou uso válido, renderiza mensagem de erro
            if (!uso_id) {
                return res.render('mensagemMulta', {
                    mensagem: "Não rolou associar um motorista. Cadastre um uso pra esse período.",
                    csrfToken: req.csrfToken(),
                    layout: 'layout',
                    activePage: 'registrar-multa',
                    user: req.user
                });
            }

            // Agora insere a multa
            const insertQuery = `
          INSERT INTO multas (veiculo_id, motorista, data, multa, uso_id)
          VALUES (?, ?, ?, ?, ?)
        `;
            const motoristaProvavel = usoResult[0].motorista;

            db.query(
                insertQuery,
                [veiculo_id, motoristaProvavel, data_multa, multa, uso_id],
                (insertErr) => {
                    if (insertErr) {
                        console.error("Erro ao registrar a multa:", insertErr);
                        return res.status(500).send("Erro ao registrar a multa.");
                    }
                    res.redirect("/relatorio-multas");
                }
            );
        });
    }
);


app.get('/relatorio-multas', isAuthenticated, csrfProtection, (req, res) => {
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
            csrfToken: req.csrfToken(),
            title: 'Relatório de Multas',
            layout: 'layout',
            activePage: 'relatorio-multas',
            user: req.user
        });
    });
});

app.get('/editar-uso/:id', isAuthenticated, csrfProtection, (req, res) => {
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
                csrfToken: req.csrfToken(),
                multas: multasResult,
                title: 'Editar Uso',
                layout: 'layout',
                activePage: 'editarUso',
                user: req.user,
                csrfToken: req.csrfToken()
            });
        });
    });
});


app.get('/usar/:id', isAuthenticated, csrfProtection, (req, res) => {
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
                csrfToken: req.csrfToken(),
                kmInicial,
                motoristaEmail, // Passa o email do usuário autenticado
                title: 'Usar Veículo',
                layout: 'layout',
                activePage: 'usar',
                user: req.user
            });
        });
    });
});

//rota para auto gerar manutenção

function autoGenerateMaintenance(veiculo) {
   // console.log(`🔍 Verificando manutenção para veículo ${veiculo.id} (${veiculo.placa}) com KM=${veiculo.km}`);

    const regrasManutencao = [
        { tipo: 'Troca de Pneus', kmIntervalo: 100 },
        { tipo: 'Rodízio de Pneus', kmIntervalo: 100 },
        { tipo: 'Troca de Pastilhas', kmIntervalo: 100 },
        { tipo: 'Troca de Discos de Freio', kmIntervalo: 100 },
        { tipo: 'Troca da Correia Dentada', kmIntervalo: 100 },
        { tipo: 'Troca do Óleo do Motor', kmIntervalo: 100 },
        { tipo: 'Troca do Filtro de Óleo', kmIntervalo: 100 },
        { tipo: 'Troca do Filtro de Ar', kmIntervalo: 100 },
        { tipo: 'Troca do Filtro de Combustível', kmIntervalo: 100 },
        { tipo: 'Alinhamento e Balanceamento', kmIntervalo: 100 },
        { tipo: 'Verificação do Sistema de Arrefecimento', kmIntervalo: 100 },
        { tipo: 'Revisão do Sistema Elétrico', kmIntervalo: 100 },
        { tipo: 'Inspeção dos Níveis (água, freio, etc.)', kmIntervalo: 100 },
        { tipo: 'Troca do Líquido de Arrefecimento', kmIntervalo: 100 },
        { tipo: 'Troca do Líquido de Freio', kmIntervalo: 100 },
        { tipo: 'Troca do Líquido da Direção Hidráulica', kmIntervalo: 100 },
        { tipo: 'Troca das Velas de Ignição', kmIntervalo: 100 },
        { tipo: 'Inspeção da Suspensão e Amortecedores', kmIntervalo: 100 },
        { tipo: 'Inspeção da Bateria', kmIntervalo: 100 },
        { tipo: 'Inspeção do Sistema de Escape', kmIntervalo: 100 },
        { tipo: 'Verificação dos Cabos e Correias', kmIntervalo: 100 }
    ];



    regrasManutencao.forEach(regra => {
        if (Number(veiculo.km) >= regra.kmIntervalo) {
            //console.log(`⚠️ Veículo ${veiculo.id} ultrapassou ${regra.kmIntervalo} km para ${regra.tipo}`);

            const queryVerifica = `
              SELECT * FROM manutencoes 
              WHERE veiculo_id = ? AND tipo = ? AND status = 'pendente'
            `;
            db.query(queryVerifica, [veiculo.id, regra.tipo], (err, results) => {
                if (err) {
                    console.error(`Erro ao verificar manutenção ${regra.tipo}:`, err);
                    return;
                }
                //console.log(`Resultado da verificação para ${regra.tipo}: ${results.length} registros encontrados.`);
                if (results.length === 0) {
                    const descricao = `Manutenção automática disparada ao atingir ${veiculo.km} km.`;
                    const queryInsert = `
                       INSERT INTO manutencoes (veiculo_id, tipo, descricao, km_agendado, status)
                       VALUES (?, ?, ?, ?, 'pendente')
                    `;
                    //console.log(`Tentando inserir manutenção "${regra.tipo}" para o veículo ${veiculo.placa}.`);
                    db.query(queryInsert, [veiculo.id, regra.tipo, descricao, regra.kmIntervalo], (err, result) => {
                        if (err) {
                            console.error(`Erro ao inserir manutenção ${regra.tipo}:`, err);
                        } else {
                            //console.log(`✅ Manutenção "${regra.tipo}" gerada para o veículo ${veiculo.placa}.`);
                            sendMaintenanceNotification(veiculo, { tipo: regra.tipo, descricao });
                        }
                    });
                } else {
                    //console.log(`✅ Já existe manutenção pendente para ${regra.tipo} no veículo ${veiculo.placa}.`);
                }
            });
        } else {
           // console.log(`Veículo ${veiculo.id} com KM=${veiculo.km} não atingiu ${regra.kmIntervalo} para ${regra.tipo}.`);
        }
    });
}

// Parser Multer para um único arquivo foto_km
const uploadSingleFoto = multer({
    storage,
    limits: { fileSize: 1000 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (!file.mimetype.startsWith('image/')) {
            return cb(new Error('Só imagens são permitidas'), false);
        }
        cb(null, true);
    }
}).single('foto_km');

app.post('/usar/:id', isAuthenticated, uploadSingleFoto, csrfProtection, (req, res) => {
    const { id } = req.params; // ID do veículo

    const { km_inicial, km_final, data_hora_inicial, data_hora_final, finalidade, descricao } = req.body;
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

                    // Insere o registro de uso incluindo os novos campos
                    db.query(
                        'INSERT INTO uso_veiculos (veiculo_id, motorista, km_inicial, km_final, data_hora_inicial, data_hora_final, foto_km, finalidade, descricao) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        [id, motoristaEmail, km_inicial, kmFinalValue, dataHoraInicial, dataHoraFinal, foto_km, finalidade, descricao],
                        (err, result) => {
                            if (err) throw err;

                            // Se km_final for informado, atualiza o km do veículo e dispara verificações
                            if (kmFinalValue !== null) {
                                db.query('UPDATE veiculos SET km = ? WHERE id = ?', [kmFinalValue, id], (err, result2) => {
                                    if (err) {
                                        console.error("Erro ao atualizar km:", err);
                                    } else {
                                       // console.log(` Veículo ${id} atualizado para km=${kmFinalValue}`);
                                        // Verifica troca de óleo
                                        checkOilChangeForVehicle(id);
                                        // Busca dados atualizados do veículo e chama autoGenerateMaintenance
                                        db.query('SELECT * FROM veiculos WHERE id = ?', [id], (err, updatedResult) => {
                                            if (err) {
                                                console.error("Erro ao buscar veículo atualizado:", err);
                                            } else if (updatedResult.length > 0) {
                                                //console.log(" Dados atualizados do veículo:", updatedResult[0]);
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


const uploadOptionalFoto = multer({
    storage,
    limits: { fileSize: 1000 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (!file.mimetype.startsWith('image/')) {
            return cb(new Error('Só imagens são permitidas'), false);
        }
        cb(null, true);
    }
}).single('foto_km');

app.post(
    '/editar-uso/:id',
    isAuthenticated,
    uploadOptionalFoto,   // Multer parseia multipart/form-data
    csrfProtection,      // depois valida CSRF
    (req, res) => {
        const { id } = req.params;
        const {
            motorista,
            km_final,
            data_hora_final,
            multas_id,
            multas_descricao,
            finalidade,
            descricao
        } = req.body;

        // 1) Permissão: só o próprio motorista
        if (req.user && req.user.email !== motorista) {
            return res.status(403).send('Você não tem permissão para editar este uso.');
        }

        // 2) Novas multas em array
        const novasMultas = req.body.novasMultas
            ? [].concat(req.body.novasMultas).filter(m => m.trim().length > 0)
            : [];

        // 3) Função auxiliar de render de erro
        function renderError(message) {
            db.query("SELECT * FROM uso_veiculos WHERE id = ?", [id], (err, results) => {
                if (err || results.length === 0) {
                    return res.status(500).send("Erro ao carregar dados para exibição de erro.");
                }
                const uso = results[0];
                res.render('editarUso', {
                    uso,
                    errorMessage: message,
                    csrfToken: req.csrfToken()
                });
            });
        }

        // 4) Validações pré-update
        if ((km_final && km_final !== '') || (data_hora_final && data_hora_final !== '')) {
            db.query(
                "SELECT km_inicial, data_hora_inicial FROM uso_veiculos WHERE id = ?",
                [id],
                (err, resultSelect) => {
                    if (err) {
                        console.error("Erro na verificação:", err);
                        return renderError("Erro interno ao verificar os dados.");
                    }
                    const row = resultSelect[0];
                    const kmInicialValue = parseInt(row.km_inicial, 10);

                    // KM final inválido / menor que o inicial
                    if (km_final && km_final !== '') {
                        const kmParsed = parseInt(km_final, 10);
                        if (isNaN(kmParsed)) {
                            return renderError('KM final inválido.');
                        }
                        if (kmParsed <= kmInicialValue) {
                            return renderError('KM final não pode ser menor que KM inicial.');
                        }
                        // limite de autonomia
                        const autonomiaUno = 700;
                        if (kmParsed - kmInicialValue > autonomiaUno) {
                            return renderError(`O consumo (${kmParsed - kmInicialValue} km) ultrapassa a autonomia (${autonomiaUno} km).`);
                        }
                    }

                    // Data final antes da inicial
                    if (data_hora_final && data_hora_final !== '') {
                        const dtFinal = new Date(data_hora_final);
                        const dtInicial = new Date(row.data_hora_inicial);
                        if (dtFinal < dtInicial) {
                            return renderError('A data final não pode ser antes da data inicial.');
                        }
                    }

                    // Se passou nas validações, continua
                    executeUpdate();
                }
            );
        } else {
            executeUpdate();
        }

        // 5) Monta e executa o UPDATE
        function executeUpdate() {
            // a) Decide se atualiza a foto pela existência de req.file
            let updateQuery, params;
            if (req.file) {
                updateQuery = `
            UPDATE uso_veiculos
            SET motorista = ?, km_final = ?, data_hora_final = ?, foto_km = ?, finalidade = ?, descricao = ?
            WHERE id = ?
          `;
                params = [
                    motorista,
                    km_final === '' ? null : km_final,
                    data_hora_final === '' ? null : data_hora_final,
                    req.file.filename,
                    finalidade,
                    descricao,
                    id
                ];
            } else {
                updateQuery = `
            UPDATE uso_veiculos
            SET motorista = ?, km_final = ?, data_hora_final = ?, finalidade = ?, descricao = ?
            WHERE id = ?
          `;
                params = [
                    motorista,
                    km_final === '' ? null : km_final,
                    data_hora_final === '' ? null : data_hora_final,
                    finalidade,
                    descricao,
                    id
                ];
            }

            // b) Executa o UPDATE principal
            db.query(updateQuery, params, (err) => {
                if (err) {
                    console.error("Erro ao atualizar uso:", err);
                    return renderError('Erro ao atualizar o uso. Por favor, tente novamente.');
                }

                // c) Atualiza multas já existentes
                if (multas_id && multas_descricao) {
                    const ids = Array.isArray(multas_id) ? multas_id : [multas_id];
                    const descr = Array.isArray(multas_descricao)
                        ? multas_descricao
                        : [multas_descricao];
                    ids.forEach((mId, idx) => {
                        db.query(
                            'UPDATE multas SET multa = ? WHERE id = ?',
                            [descr[idx], mId],
                            err => {
                                if (err) console.error(`Erro ao atualizar multa ${mId}:`, err);
                            }
                        );
                    });
                }

                // d) Se km_final veio, atualiza o km do veículo e dispara notificações
                if (km_final && km_final !== '') {
                    const kmParsed = parseInt(km_final, 10);
                    if (!isNaN(kmParsed)) {
                        db.query(
                            "SELECT veiculo_id FROM uso_veiculos WHERE id = ?",
                            [id],
                            (err, r2) => {
                                if (!err && r2.length) {
                                    const veiculo_id = r2[0].veiculo_id;
                                    db.query(
                                        "UPDATE veiculos SET km = ? WHERE id = ?",
                                        [kmParsed, veiculo_id],
                                        err => {
                                            if (err) console.error("Erro ao atualizar km do veículo:", err);
                                            else {
                                                checkOilChangeForVehicle(veiculo_id);
                                                db.query(
                                                    "SELECT * FROM veiculos WHERE id = ?",
                                                    [veiculo_id],
                                                    (err, up) => {
                                                        if (!err && up.length) {
                                                            autoGenerateMaintenance(up[0]);
                                                        }
                                                    }
                                                );
                                            }
                                        }
                                    );
                                }
                            }
                        );
                    }
                }

                // e) Insere novas multas, se houver
                if (novasMultas.length > 0) {
                    db.query(
                        "SELECT veiculo_id FROM uso_veiculos WHERE id = ?",
                        [id],
                        (err, r5) => {
                            if (err || !r5.length) {
                                return renderError("Erro ao buscar veículo para novas multas.");
                            }
                            const veiculo_id = r5[0].veiculo_id;
                            const valores = novasMultas.map(m => [id, veiculo_id, m.trim()]);
                            db.query(
                                "INSERT INTO multas (uso_id, veiculo_id, multa) VALUES ?",
                                [valores],
                                err => {
                                    if (err) {
                                        console.error("Erro ao registrar novas multas:", err);
                                        return renderError("Erro ao registrar novas multas.");
                                    }
                                    return res.redirect('/relatorio-uso');
                                }
                            );
                        }
                    );
                } else {
                    // f) Se não há novas multas, só redireciona
                    res.redirect('/relatorio-uso');
                }
            });
        }
    }
);






// Rota pra marcar que a troca de óleo foi feita
app.post('/troca-feita/:id', isAuthenticated, isAdmin, csrfProtection, (req, res) => {
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
app.post('/excluir-multa/:id', isAuthenticated, isAdmin, csrfProtection, (req, res) => {
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
app.post('/excluir-uso/:id', isAuthenticated, isAdmin, csrfProtection, (req, res) => {
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

app.post('/excluir-multiplos-usos', isAuthenticated, isAdmin, csrfProtection, (req, res) => {
    let { ids } = req.body;

    if (!ids) {
        return res.status(400).json({ message: 'IDs inválidos.' });
    }

    // Certifica  que `ids` seja um array de números
    if (typeof ids === 'string') {
        ids = ids.split(',').map(id => Number(id.trim()));
    }
    if (!Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ message: 'IDs inválidos.' });
    }

    //console.log('IDs para exclusão:', ids);

    // Obtém uma conexão do pool
    db.getConnection((err, connection) => {
        if (err) {
            console.error('Erro ao obter conexão:', err);
            return res.status(500).json({ message: 'Erro ao obter conexão.' });
        }

        connection.beginTransaction(err => {
            if (err) {
                connection.release();
                console.error('Erro ao iniciar transação:', err);
                return res.status(500).json({ message: 'Erro ao iniciar transação.' });
            }

            // Corrige a query de DELETE para múltiplos IDs
            const placeholders = ids.map(() => '?').join(',');
            const queryMultas = `DELETE FROM multas WHERE uso_id IN (${placeholders})`;

            connection.query(queryMultas, ids, (err, resultMultas) => {
                if (err) {
                    console.error('Erro ao excluir multas:', err);
                    return connection.rollback(() => {
                        connection.release();
                        res.status(500).json({ message: 'Erro ao excluir multas.' });
                    });
                }

                const queryUso = `DELETE FROM uso_veiculos WHERE id IN (${placeholders})`;

                connection.query(queryUso, ids, (err, resultUso) => {
                    if (err) {
                        console.error('Erro ao excluir usos:', err);
                        return connection.rollback(() => {
                            connection.release();
                            res.status(500).json({ message: 'Erro ao excluir usos.' });
                        });
                    }

                    if (resultUso.affectedRows === 0) {
                        return connection.rollback(() => {
                            connection.release();
                            res.status(404).json({ message: 'Nenhum registro encontrado.' });
                        });
                    }

                    connection.commit(err => {
                        if (err) {
                            console.error('Erro ao commitar transação:', err);
                            return connection.rollback(() => {
                                connection.release();
                                res.status(500).json({ message: 'Erro ao finalizar exclusão.' });
                            });
                        }
                        connection.release();
                        res.json({ message: 'Registros excluídos com sucesso.' });
                    });
                });
            });
        });
    });
});



// Rota para exibir a tela de edição do veículo
app.get('/editar-veiculo/:id', isAuthenticated, csrfProtection, (req, res) => {
    const id = req.params.id;
    db.query("SELECT * FROM veiculos WHERE id = ?", [id], (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).send("Veículo não encontrado.");
        }
        res.render('editar-veiculo', {
            veiculo: results[0],
            csrfToken: req.csrfToken(),
            title: 'Editar Veículo',
            layout: 'layout',
            activePage: 'editar-veiculo',
            user: req.user // Passa o usuário autenticado para o template
        });
    });
});

// Rota para atualizar dados do veículo
app.post('/editar-veiculo/:id', isAuthenticated, csrfProtection, (req, res) => {
    const id = req.params.id;
    const { nome, placa, km, ultimaTrocaOleo, modelo, ano, cor, justificativaKm } = req.body;

    // Obtém o km atual para comparação
    db.query("SELECT km AS currentKm FROM veiculos WHERE id = ?", [id], (err, resultVehicle) => {
        if (err) {
            console.error("Erro ao buscar dados do veículo:", err);
            return res.status(500).send("Erro interno ao buscar dados do veículo.");
        }
        if (resultVehicle.length === 0) {
            return res.status(404).send("Veículo não encontrado.");
        }
        const currentKm = parseInt(resultVehicle[0].currentKm, 10);

        // Se a quilometragem for alterada, a justificativa deve ser informada
        if (parseInt(km, 10) !== currentKm && (!justificativaKm || !justificativaKm.trim())) {
            return res.status(400).send("Justificativa é obrigatória ao alterar a quilometragem.");
        }

        // Verifica se há uso em andamento para este veículo
        db.query(
            "SELECT COUNT(*) AS count FROM uso_veiculos WHERE veiculo_id = ? AND (km_final IS NULL OR data_hora_final IS NULL)",
            [id],
            (err, result) => {
                if (err) {
                    console.error("Erro ao verificar uso em andamento:", err);
                    return res.status(500).send("Erro ao verificar uso em andamento.");
                }
                if (result[0].count > 0) {
                    return res.status(400).send("Não é possível atualizar o veículo, pois há um uso em andamento.");
                } else {
                    db.query(
                        "UPDATE veiculos SET nome = ?, placa = ?, km = ?, ultimaTrocaOleo = ?, modelo = ?, ano = ?, cor = ? WHERE id = ?",
                        [nome, placa, km, ultimaTrocaOleo, modelo, ano, cor, id],
                        (err) => {
                            if (err) {
                                console.error("Erro ao atualizar veículo:", err);
                                return res.status(500).send("Erro ao atualizar veículo.");
                            }

                            // Se a quilometragem foi alterada, insere uma notificação com a justificativa
                            const userEmail = req.user ? req.user.email : 'E-mail não disponível';
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
    });
});



app.post(
    '/excluir-veiculo/:id',
    isAuthenticated,
    isAdmin,
    csrfProtection,
    async (req, res) => {
        const id = req.params.id;
        try {
            // 1) Exclui manutenções
            await query('DELETE FROM manutencoes    WHERE veiculo_id = ?', [id]);
            // 2) Exclui multas
            await query('DELETE FROM multas         WHERE veiculo_id = ?', [id]);
            // 3) Exclui usos de veículo
            await query('DELETE FROM uso_veiculos   WHERE veiculo_id = ?', [id]);

            // 4) Agora sim exclui o veículo
            await query('DELETE FROM veiculos       WHERE id = ?', [id]);

            return res.redirect('/');
        } catch (err) {
            console.error('Erro ao excluir veículo:', err);
            // Se for erro de FK, avise de outro jeito:
            if (err.code === 'ER_ROW_IS_REFERENCED_2') {
                return res.status(400).send('Ainda existem dados dependentes. Limpe multas, manutenções e usos antes.');
            }
            return res.status(500).send('Erro ao excluir veículo.');
        }
    }
);


// Rota de notificações: mostra veículos que precisam trocar óleo e notificações de alteração de quilometragem
app.get('/notificacoes', isAuthenticated, isAdmin, csrfProtection, (req, res) => {
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
                csrfToken: req.csrfToken(),
                kmNotifications: notifResults,
                title: 'Notificações',
                layout: 'layout',
                activePage: 'notificacoes',
                user: req.user // Passa o usuário autenticado para o template
            });
        });
    });
});

app.post('/excluir-notificacao-alteracao-km/:id', isAuthenticated, isAdmin, csrfProtection, async (req, res) => {
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

app.get('/registro-motorista', isAuthenticated, csrfProtection, async (req, res) => {
    try {
        // Verifica se já existe um registro de motorista com o email do usuário
        const resultados = await query(
            'SELECT * FROM motoristas WHERE email = ?',
            [req.user.email]
        );

        const jaCadastrado = resultados.length > 0;
        const motorista = jaCadastrado ? resultados[0] : null;

        //  Renderiza a view, sempre passando errors, errorFields e data (mesmo vazios)
        res.render('registro-motorista', {
            activePage: 'registro-motorista',
            user: req.user,
            csrfToken: req.csrfToken(),
            title: 'Cadastro de Motorista',
            layout: 'layout',
            isMotorista: jaCadastrado,    // flag para o EJS
            motorista,                     // dados do motorista (se existir)
            errors: [],
            errorFields: [],
            data: {}
        });
    } catch (err) {
        console.error('Erro ao buscar motorista:', err);
        res.status(500).send('Erro interno');
    }
});





// Rota para cadastro de motoristas
app.post('/api/cadastro-motorista', isAuthenticated, upload.single('foto'), csrfProtection, async (req, res) => {
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
app.get('/registrar-manutencao/:veiculo_id', isAuthenticated, isAdmin, csrfProtection, (req, res) => {
    const { veiculo_id } = req.params;
    db.query("SELECT * FROM veiculos WHERE id = ?", [veiculo_id], (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).send("Veículo não encontrado.");
        }
        const veiculo = results[0];
        res.render('registrar-manutencao', {
            title: 'Registrar Manutenção',
            csrfToken: req.csrfToken(),
            layout: 'layout',
            activePage: 'manutencao',
            veiculo,
            tipos: ['Rodízio de Pneus', 'Troca de Pneus', 'Troca de Pastilhas', 'Troca de Discos de Freio']
        });
    });
});

// Rota para processar cadastro de manutenção
app.post('/registrar-manutencao/:veiculo_id', isAuthenticated, isAdmin, csrfProtection, (req, res) => {
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
app.get('/manutencoes', isAuthenticated, csrfProtection, (req, res) => {
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
            csrfToken: req.csrfToken(),
            layout: 'layout',
            activePage: 'manutencoes',
            manutencoes: results,
            user: req.user // Passa o usuário autenticado para o template
        });
    });
});

// Rota para marcar uma manutenção como realizada
app.post('/manutencoes/realizada/:id', isAuthenticated, isAdmin, csrfProtection, (req, res) => {
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
app.post('/reembolsos', upload.single('comprovante'), isAuthenticated, csrfProtection, async (req, res) => {
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
// Rota para exibir o formulário, a lista de reembolsos detalhados, os dados para o gráfico e os reembolsos agregados
app.get('/reembolsos', isAuthenticated, csrfProtection, async (req, res) => {
    try {
        // Consulta para buscar os reembolsos detalhados com os dados do motorista
        const reembolsos = await query(`
            SELECT r.*, m.nome as motorista_nome 
            FROM reembolsos r 
            JOIN motoristas m ON r.motorista_id = m.id 
            ORDER BY r.criado_em ASC
        `);

        // Consulta para buscar motoristas para o formulário
        const motoristas = await query('SELECT id, nome FROM motoristas');

        // Agregação diária: soma dos valores de reembolso por motorista e por dia
        const reembolsoDiario = await query(`
            SELECT 
              m.nome as motorista_nome,
              DATE(r.criado_em) AS dia,
              ROUND(SUM(r.valor), 2) AS total_reembolso
            FROM reembolsos r
            JOIN motoristas m ON r.motorista_id = m.id
            GROUP BY m.nome, DATE(r.criado_em)
            ORDER BY DATE(r.criado_em) DESC, m.nome
        `);

        // Agregação mensal: soma dos valores de reembolso por motorista e por mês
        const reembolsoMensal = await query(`
            SELECT 
              m.nome as motorista_nome,
              DATE_FORMAT(r.criado_em, '%Y-%m') AS mes,
              ROUND(SUM(r.valor), 2) AS total_reembolso
            FROM reembolsos r
            JOIN motoristas m ON r.motorista_id = m.id
            GROUP BY m.nome, DATE_FORMAT(r.criado_em, '%Y-%m')
            ORDER BY DATE_FORMAT(r.criado_em, '%Y-%m') DESC, m.nome
        `);

        // Agregação anual: soma dos valores de reembolso por motorista e por ano
        const reembolsoAnual = await query(`
            SELECT 
              m.nome as motorista_nome,
              YEAR(r.criado_em) AS ano,
              ROUND(SUM(r.valor), 2) AS total_reembolso
            FROM reembolsos r
            JOIN motoristas m ON r.motorista_id = m.id
            GROUP BY m.nome, YEAR(r.criado_em)
            ORDER BY YEAR(r.criado_em) DESC, m.nome
        `);

        // Renderiza a view enviando os dados para a tabela detalhada, gráfico e agregações
        res.render('reembolsos', {
            reembolsos,
            csrfToken: req.csrfToken(),
            motoristas,
            reembolsosGrafico: reembolsos, // mesma lista utilizada para o gráfico
            reembolsoDiario,
            reembolsoMensal,
            reembolsoAnual,
            title: 'Gerenciar Reembolsos',
            activePage: 'reembolsos',
            user: req.user // Passa o usuário autenticado para o template
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro no servidor');
    }
});


app.get('/relatorio-consumo', isAuthenticated, csrfProtection, async (req, res) => {
    try {
        // 1) Parâmetros de busca
        const { motorista, startDate, endDate } = req.query;

        // 2) Constantes de negócio
        const eficiencia = 10;       // km por litro
        const precoGasolina = 6.45;  // R$

        // 3) Carrega a lista de motoristas (id e email) para popular o <select>
        const motoristasList = await query(
            'SELECT id, email FROM motoristas ORDER BY email'
        );

        // 4) Constrói os filtros dinâmicos
        const filters = ['uso.km_final IS NOT NULL'];
        const params = [];

        if (motorista) {
            filters.push('LOWER(TRIM(motoristas.email)) = LOWER(TRIM(?))');
            params.push(motorista);
        }
        if (startDate) {
            filters.push('DATE(uso.data_criacao) >= ?');
            params.push(startDate);
        }
        if (endDate) {
            filters.push('DATE(uso.data_criacao) <= ?');
            params.push(endDate);
        }
        const whereClause = filters.length ? 'WHERE ' + filters.join(' AND ') : '';

        // 5) Função auxiliar para agregar consumo e custo (reembolso) por período
        const agregar = async (groupExpr, label) => {
            const sql = `
          SELECT
            motoristas.email AS motorista,
            ${groupExpr} AS ${label},
            ROUND(SUM((uso.km_final - uso.km_inicial) / ?), 2) AS consumo_estimado,
            ROUND(SUM((uso.km_final - uso.km_inicial) / ? * ?), 2) AS custo_estimado
          FROM uso_veiculos AS uso
          JOIN veiculos ON uso.veiculo_id = veiculos.id
          JOIN motoristas ON motoristas.email = uso.motorista
          ${whereClause}
          GROUP BY motoristas.email, ${groupExpr}
          ORDER BY ${groupExpr} DESC, motoristas.email
            `;
            //console.log('SQL:', sql);
            return await query(sql, [eficiencia, eficiencia, precoGasolina, ...params]);
        };

        // 6) Função auxiliar para agregar apenas reembolso (baseado no custo)
        const agregarReembolso = async (groupExpr, label) => {
            const sql = `
          SELECT
            motoristas.email AS motorista,
            ${groupExpr} AS ${label},
            ROUND(SUM((uso.km_final - uso.km_inicial) / ? * ?), 2) AS reembolso
          FROM uso_veiculos AS uso
          JOIN veiculos ON uso.veiculo_id = veiculos.id
          JOIN motoristas ON motoristas.email = uso.motorista
          ${whereClause}
          GROUP BY motoristas.email, ${groupExpr}
          ORDER BY ${groupExpr} DESC, motoristas.email
            `;
            //console.log('SQL Reembolso:', sql);
            return await query(sql, [eficiencia, precoGasolina, ...params]);
        };

        // 7) Executa as agregações para consumo/custo e para reembolso
        const resumoDiario = await agregar("DATE(uso.data_criacao)", "dia");
        const resumoMensal = await agregar("DATE_FORMAT(uso.data_criacao, '%Y-%m')", "mes");
        const resumoAnual = await agregar("YEAR(uso.data_criacao)", "ano");

        const reembolsoDiario = await agregarReembolso("DATE(uso.data_criacao)", "dia");
        const reembolsoMensal = await agregarReembolso("DATE_FORMAT(uso.data_criacao, '%Y-%m')", "mes");
        const reembolsoAnual = await agregarReembolso("YEAR(uso.data_criacao)", "ano");

        // 8) Renderiza a view, passando os resumos de consumo e reembolso
        res.render('relatorioConsumo', {
            title: 'Relatório de Consumo e Reembolso por Motorista',
            activePage: 'relatorioConsumo',
            filtro: { motorista, startDate, endDate },
            csrfToken: req.csrfToken(),
            motoristasList,
            resumoDiario,
            resumoMensal,
            resumoAnual,
            reembolsoDiario,
            reembolsoMensal,
            reembolsoAnual,
            user: req.user,
            // Passa o usuário autenticado para o template
            activePage: 'relatorio-consumo',
        });

    } catch (err) {
        console.error(err);
        res.status(500).send('Erro no servidor ao gerar relatório.');
    }
});




////////////////////////////////////////////////////////////////////////////////////

app.get('/search', isAuthenticated, csrfProtection, async (req, res) => {
    const q = req.query.q || '';
    // Se não houver consulta, renderiza a view sem resultados
    if (!q.trim()) {
        return res.render('searchResults', {
            q,
            results: {},
            user: req.user
        });
    }

    try {
        // Busca em veículos (id, nome e placa)
        const veiculos = await query(
            `SELECT id, nome, placa 
             FROM veiculos 
             WHERE id = ? 
               OR nome LIKE ? 
               OR placa LIKE ?`,
            [q, `%${q}%`, `%${q}%`]
        );

        // Busca em usos de veículos (id e motorista)
        const usos = await query(
            `SELECT id, motorista, km_inicial, km_final 
             FROM uso_veiculos 
             WHERE id = ? 
               OR motorista LIKE ?`,
            [q, `%${q}%`]
        );

        // Busca em multas (id e descrição)
        const multas = await query(
            `SELECT id, multa, motorista 
             FROM multas 
             WHERE id = ? 
               OR multa LIKE ?`,
            [q, `%${q}%`]
        );

        // Busca em motoristas (id, nome e CPF)
        const motoristas = await query(
            `SELECT id, nome, cpf 
             FROM motoristas 
             WHERE id = ? 
               OR nome LIKE ? 
               OR cpf LIKE ?`,
            [q, `%${q}%`, `%${q}%`]
        );

        const results = { veiculos, usos, multas, motoristas };

        // Renderiza passando sempre o usuário autenticado
        res.render('searchResults', {
            q,
            csrfToken: req.csrfToken(),
            results,
            user: req.user
        });

    } catch (err) {
        console.error(err);
        res.status(500).send("Erro no servidor ao realizar busca.");
    }
});

/*
/// API FIPE
const axios = require('axios');

// Função auxiliar para converter preço formatado ("R$ 10.000,00") em número
function parsePrice(priceStr) {
    // Remove "R$" e espaços, remove pontos e troca vírgula por ponto
    const numStr = priceStr.replace('R$', '').trim().replace(/\./g, '').replace(',', '.');
    return parseFloat(numStr);
  }
  
  // Rota para exibir dados dos veículos e a análise de custo de conserto vs. valor FIPE
  app.get('/veiculos', async (req, res) => {
    try {
      // Para fins de demonstração usamos:
      // Tipo: "cars"
      // Marca: código 59 (VW - VolksWagen)
      // Modelo: código 5940 (um modelo específico)
      const vehicleType = 'cars';
      const brandId = 59;
      const modelId = 5940;
  
      // Endpoint para obter os anos disponíveis para este modelo
      const yearsUrl = `https://parallelum.com.br/fipe/api/v2/${vehicleType}/brands/${brandId}/models/${modelId}/years`;
      const yearsResponse = await axios.get(yearsUrl);
      const years = yearsResponse.data; // array de objetos com { code, name }
  
      // Array para armazenar os dados finais dos veículos
      const veiculos = [];
  
      // Para cada ano disponível, obtenha os detalhes (FIPE info)
      for (let yearObj of years) {
        const yearId = yearObj.code; // ex: "2014-3"
        const infoUrl = `https://parallelum.com.br/fipe/api/v2/${vehicleType}/brands/${brandId}/models/${modelId}/years/${yearId}`;
        const infoResponse = await axios.get(infoUrl);
        const fipeInfo = infoResponse.data;
        
        // Obtenha o valor FIPE em número
        const fipeValue = parsePrice(fipeInfo.price);
  
        // Para simular o custo de conserto, vamos gerar um valor aleatório entre 50% e 120% do valor FIPE
        const randomFactor = Math.random() * (1.20 - 0.50) + 0.50; // valor entre 0.50 e 1.20
        const custoConserto = fipeValue * randomFactor;
        const percentualConserto = (custoConserto / fipeValue) * 100;
  
        // Se o custo do conserto for menor ou igual a 70% do valor FIPE, vale a pena consertar; senão, leilão
        const decision = percentualConserto <= 70 ? 'Vale a pena consertar' : 'Indicado para leilão';
  
        veiculos.push({
          brand: fipeInfo.brand,
          modelo: fipeInfo.model,
          ano: fipeInfo.modelYear,
          precoFipe: fipeInfo.price,
          custoConserto: custoConserto.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' }),
          percentualConserto: percentualConserto.toFixed(2),
          decision
        });
      }
  
      // Gerar HTML com uma tabela para exibir os resultados
      let html = `
        <html>
          <head>
            <meta charset="UTF-8">
            <title>Veículos FIPE e Análise de Conserto</title>
            <style>
              table { border-collapse: collapse; width: 80%; margin: 20px auto; }
              th, td { border: 1px solid #ddd; padding: 8px; text-align: center; }
              th { background-color: #f2f2f2; }
            </style>
          </head>
          <body>
            <h1 style="text-align: center;">Dados dos Veículos (FIPE) e Análise de Conserto/Leilão</h1>
            <table>
              <thead>
                <tr>
                  <th>Marca</th>
                  <th>Modelo</th>
                  <th>Ano</th>
                  <th>Valor FIPE</th>
                  <th>Custo de Conserto</th>
                  <th>% Custo Conserto</th>
                  <th>Decisão</th>
                </tr>
              </thead>
              <tbody>
      `;
  
      veiculos.forEach(v => {
        html += `
          <tr>
            <td>${v.brand}</td>
            <td>${v.modelo}</td>
            <td>${v.ano}</td>
            <td>${v.precoFipe}</td>
            <td>${v.custoConserto}</td>
            <td>${v.percentualConserto}%</td>
            <td>${v.decision}</td>
          </tr>
        `;
      });
  
      html += `
              </tbody>
            </table>
          </body>
        </html>
      `;
  
      res.send(html);
    } catch (error) {
      console.error('Erro ao buscar dados da API FIPE:', error);
      res.status(500).send('Erro ao buscar dados da API FIPE');
    }
  });

  app.get('/api/marcas', async (req, res) => {
    try {
      const response = await axios.get('https://parallelum.com.br/fipe/api/v2/cars/brands');
      res.json(response.data);
    } catch (error) {
      console.error('Erro ao consultar marcas:', error);
      res.status(500).json({ error: 'Erro ao carregar marcas' });
    }
  });
  app.get('/api/modelos', async (req, res) => {
    const { marca } = req.query;
    if (!marca) {
      return res.status(400).json({ error: 'Marca não informada' });
    }
    try {
      const response = await axios.get(`https://parallelum.com.br/fipe/api/v2/cars/brands/${marca}/models`);
      // Se a resposta for um array, use-a diretamente, caso contrário, tente usar response.data.modelos
      const modelos = Array.isArray(response.data) ? response.data : response.data.modelos;
      res.json(modelos);
    } catch (error) {
      console.error('Erro ao consultar modelos:', error);
      res.status(500).json({ error: 'Erro ao carregar modelos' });
    }
  });
  
  app.get('/api/anos', async (req, res) => {
    const { marca, modelo } = req.query;
    if (!marca || !modelo) {
      return res.status(400).json({ error: 'Marca e modelo são obrigatórios' });
    }
    try {
      const response = await axios.get(`https://parallelum.com.br/fipe/api/v2/cars/brands/${marca}/models/${modelo}/years`);
      res.json(response.data);
    } catch (error) {
      console.error('Erro ao consultar anos:', error);
      res.status(500).json({ error: 'Erro ao carregar anos' });
    }
  });


  */
////////////////////////////////////////////////////////////////conserto viavel ou nao
const axios = require('axios');

//
// --- ROTA GET /conserto-viavel ---
//  query tem que trazer os campos marca e marca_nome
app.get('/conserto-viavel', isAuthenticated, csrfProtection, async (req, res) => {
    try {
        const registros = await query(`
        SELECT 
          id, marca, marca_nome, modelo, modelo_nome,
          ano, valor_fipe, custo_conserto, conserto_viavel, dataCadastro
        FROM carro_reparo
        ORDER BY dataCadastro DESC
      `);

        // render de sucesso: inclui user
        res.render('conserto-viavel', {
            user: req.user,
            csrfToken: req.csrfToken(),
            registros,
            activePage: 'conserto-viavel',
        });
    } catch (err) {
        console.error('Erro ao buscar registros:', err);
        // render de erro:  inclui user
        res.render('conserto-viavel', {
            user: req.user,
            csrfToken: req.csrfToken(),
            registros: [],
            activePage: 'conserto-viavel',
        });
    }
});


// --- ROTA POST /salvar-avaliacao ---
app.post('/salvar-avaliacao', isAuthenticated, csrfProtection, (req, res) => {
    // Extração dos dados incluindo os dois campos para a marca
    const { marca, marca_nome, modelo, modelo_nome, ano, valor_fipe, custo_conserto, conserto_viavel } = req.body;

    const sql = `
    INSERT INTO carro_reparo (marca, marca_nome, modelo, modelo_nome, ano, valor_fipe, custo_conserto, conserto_viavel)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `;
    const params = [marca, marca_nome, modelo, modelo_nome, ano, valor_fipe, custo_conserto, conserto_viavel];

    db.query(sql, params, (err, result) => {
        if (err) {
            console.error("Erro ao salvar avaliação:", err);
            return res.status(500).json({ error: 'Erro ao salvar avaliação.' });
        }
        res.json({ sucesso: true, mensagem: 'Avaliação salva com sucesso.' });
    });
});

// --- ROTA POST /conserto-viavel (Avalia viabilidade sem salvar) ---

app.post('/conserto-viavel', isAuthenticated, csrfProtection, async (req, res) => {
    try {
        const { marca, modelo, ano: anoCodigo, custo_conserto } = req.body;
        if (!marca || !modelo || !anoCodigo || !custo_conserto) {
            return res.status(400).json({ sucesso: false, error: 'Dados incompletos.' });
        }

        // Consulta FIPE
        const urlFipe = `https://parallelum.com.br/fipe/api/v1/carros/marcas/${marca}/modelos/${modelo}/anos/${anoCodigo}`;
        const { data: fipeData } = await axios.get(urlFipe);
        const valorStr = fipeData.Valor; // ex: "R$ 50.000,00"
        const valor_fipe = parseFloat(
            valorStr.replace(/[R$\s.]/g, '').replace(',', '.')
        );

        const percentual = (parseFloat(custo_conserto) / valor_fipe) * 100;
        const conserto_viavel = percentual <= 70;
        // extrai só o ano numérico do código "1992-1"
        const ano_numero = parseInt(anoCodigo.split('-')[0], 10);

        return res.json({
            sucesso: true,
            csrfToken: req.csrfToken(),
            valor_fipe,
            percentual_custo: percentual,
            conserto_viavel,
            mensagem: conserto_viavel
                ? 'Vale a pena fazer o conserto.'
                : 'Não vale a pena o conserto, pois o custo ultrapassa 70% do valor do carro.',
            ano_numero,
            //user: req.user // Passa o usuário autenticado para o template
        });
    } catch (error) {
        console.error('Erro na rota /conserto-viavel:', error);
        return res.status(500).json({ sucesso: false, error: error.message });
    }
});

// --- Rotas da API FIPE  ---
app.get('/api/marcas', isAuthenticated, csrfProtection, async (req, res) => {
    try {
        const { data } = await axios.get(
            'https://parallelum.com.br/fipe/api/v1/carros/marcas'
        );
        res.json({ sucesso: true, marcas: data });
    } catch (error) {
        res.status(500).json({ sucesso: false, error: error.message });
    }
});


app.get('/api/modelos', isAuthenticated, csrfProtection, async (req, res) => {
    const { marca } = req.query;
    if (!marca) {
        return res.status(400).json({ sucesso: false, error: 'Marca obrigatória.' });
    }
    try {
        const { data } = await axios.get(
            `https://parallelum.com.br/fipe/api/v1/carros/marcas/${marca}/modelos`
        );
        res.json({ sucesso: true, modelos: data.modelos });
    } catch (error) {
        res.status(500).json({ sucesso: false, error: error.message });
    }
});

app.get('/api/anos', isAuthenticated, csrfProtection, async (req, res) => {
    const { marca, modelo } = req.query;
    if (!marca || !modelo) {
        return res
            .status(400)
            .json({ sucesso: false, error: 'Marca e modelo obrigatórios.' });
    }
    try {
        const { data } = await axios.get(
            `https://parallelum.com.br/fipe/api/v1/carros/marcas/${marca}/modelos/${modelo}/anos`
        );
        res.json({ sucesso: true, anos: data });
    } catch (error) {
        res.status(500).json({ sucesso: false, error: error.message });
    }
});

app.post('/excluir-avaliacao/:id', isAuthenticated, csrfProtection, async (req, res) => {
    const { id } = req.params;
    //console.log("Tentando excluir avaliação com id:", id);
    try {
        const result = await query("DELETE FROM carro_reparo WHERE id = ?", [id]);
        //console.log("Resultado da exclusão:", result);
        // Verifica se algum registro foi afetado
        if (result.affectedRows === 0) {
            return res.status(404).json({ sucesso: false, error: "Registro não encontrado." });
        }
        res.json({ sucesso: true, mensagem: "Registro excluído com sucesso!" });
    } catch (err) {
        console.error("Erro ao excluir avaliação:", err);
        res.status(500).json({ sucesso: false, error: "Erro interno no servidor." });
    }
});
/////////////////////////////// registro do user
app.get('/register', isAuthenticated, isAdmin, csrfProtection, (req, res) => {
    res.render('register', {
        erros: [],
        csrfToken: req.csrfToken(),
        email: '',
        senha: '',
        senha2: '',
        role: 'user',
        success_msg: '',
        error_msg: '',
        user: req.user,
        activePage: 'register'
    });
});

// ROTA POST - processar registro com validação de senha forte
app.post('/register', isAuthenticated, isAdmin, csrfProtection, (req, res) => {
    const { email, senha, senha2, role = 'user' } = req.body;
    const erros = [];
    let success_msg = '';
    let error_msg = '';

    // Regex de senha forte: mínimo 6 caracteres, com ao menos:
    // - 1 letra maiúscula
    // - 1 letra minúscula
    // - 1 número
    // - 1 caractere especial
    const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{6,}$/;

    // Validações básicas
    if (!email || !senha || !senha2) {
        erros.push({ msg: 'Preencha todos os campos.' });
    }
    if (senha !== senha2) {
        erros.push({ msg: 'As senhas não coincidem.' });
    }
    if (!strongPasswordRegex.test(senha)) {
        erros.push({
            msg: 'Senha fraca: use no mínimo 6 caracteres, incluindo letras maiúsculas, letras minúsculas, números e caracteres especiais.'
        });
    }
    if (!['user', 'admin'].includes(role)) {
        erros.push({ msg: 'Tipo de usuário inválido.' });
    }

    if (erros.length > 0) {
        return res.render('register', {
            erros,
            csrfToken: req.csrfToken(),
            email,
            senha: '',
            senha2: '',
            role,
            success_msg,
            error_msg,
            user: req.user
        });
    }

    // Verifica se o e-mail já existe
    pool.query('SELECT id FROM usuarios WHERE email = ?', [email], (err, results) => {
        if (err) {
            console.error(err);
            error_msg = 'Erro ao consultar o banco de dados.';
            return res.render('register', {
                erros,
                email,
                senha: '',
                senha2: '',
                role,
                success_msg,
                error_msg,
                user: req.user
            });
        }

        if (results.length > 0) {
            erros.push({ msg: 'E-mail já cadastrado.' });
            return res.render('register', {
                erros,
                email,
                senha: '',
                senha2: '',
                role,
                success_msg,
                error_msg,
                user: req.user
            });
        }

        // Hash da senha e inserção
        bcrypt.hash(senha, 12, (hashErr, hash) => {
            if (hashErr) {
                console.error(hashErr);
                error_msg = 'Erro ao gerar hash da senha.';
                return res.render('register', {
                    erros,
                    email,
                    senha: '',
                    senha2: '',
                    role,
                    success_msg,
                    error_msg,
                    user: req.user
                });
            }

            pool.query(
                'INSERT INTO usuarios (email, senha, role) VALUES (?, ?, ?)',
                [email, hash, role],
                (insertErr) => {
                    if (insertErr) {
                        console.error(insertErr);
                        error_msg = 'Erro ao cadastrar usuário.';
                        return res.render('register', {
                            erros,
                            email,
                            senha: '',
                            senha2: '',
                            role,
                            success_msg,
                            error_msg,
                            user: req.user
                        });
                    }

                    success_msg = 'Usuário cadastrado com sucesso!';
                    return res.render('register', {
                        erros: [],
                        csrfToken: req.csrfToken(),
                        email: '',
                        senha: '',
                        senha2: '',
                        role: 'user',
                        success_msg,
                        error_msg: '',
                        user: req.user
                    });
                }
            );
        });
    });
});


///////////////////////////////// fim registro user


//////////////////////////////////inicio editar usuasrios e motoristas

// LISTAR USUÁRIOS
app.get('/usuarios', isAuthenticated, csrfProtection, (req, res) => {
    pool.query('SELECT id, email, role FROM usuarios ORDER BY id', (err, results) => {
        if (err) {
            console.error(err);
            return res.sendStatus(500);
        }
        res.render('usuarios', {
            user: req.user,
            csrfToken: req.csrfToken(),
            usuarios: results,
            activePage: 'usuarios'
        });
    });
});

// LISTAR MOTORISTAS
app.get('/motoristas', isAuthenticated, csrfProtection, (req, res) => {
    pool.query(`
      SELECT 
        id, nome, email, cpf, cnh, DATE_FORMAT(data_validade, '%Y-%m-%d') AS data_validade, categoria
      FROM motoristas
      ORDER BY id
    `, (err, results) => {
        if (err) {
            console.error(err);
            return res.sendStatus(500);
        }
        res.render('motoristas', {
            user: req.user,
            csrfToken: req.csrfToken(),
            motoristas: results,
            activePage: 'motoristas'
        });
    });
});

app.delete(
    '/api/deletar-motorista/:id',
    isAuthenticated,
    csrfProtection,
    async (req, res) => {
        const { id } = req.params;
        try {
            // 1) Apaga todos os reembolsos desse motorista
            await query('DELETE FROM reembolsos WHERE motorista_id = ?', [id]);

            // 2) Em seguida, apaga o motorista
            await query('DELETE FROM motoristas WHERE id = ?', [id]);

            return res.json({
                success: true,
                message: 'Motorista e reembolsos associados excluídos com sucesso.'
            });
        } catch (err) {
            console.error('Erro ao excluir motorista:', err);
            return res
                .status(500)
                .json({ success: false, message: 'Não foi possível excluir o motorista.' });
        }
    }
);


// === EDITAR USUÁRIO ===
//  exibe formulário com email e role
app.get('/usuarios/:id/edit', isAuthenticated, csrfProtection, (req, res) => {
    const { id } = req.params;
    pool.query('SELECT id, email, role FROM usuarios WHERE id = ?', [id], (err, results) => {
        if (err || !results.length) {
            return res.redirect('/usuarios');
        }
        res.render('edit-usuario', {
            user: req.user,
            csrfToken: req.csrfToken(),
            erros: [],
            usuario: results[0]
        });
    });
});

//  valida e atualiza email e role
app.post('/usuarios/:id/edit', isAuthenticated, csrfProtection, (req, res) => {
    const { id } = req.params;
    const { email, role } = req.body;
    const erros = [];

    if (!email || !role) {
        erros.push({ msg: 'Preencha todos os campos.' });
    }
    if (!['user', 'admin'].includes(role)) {
        erros.push({ msg: 'Role inválido.' });
    }

    if (erros.length) {
        return res.render('edit-usuario', { user: req.user, erros, usuario: { id, email, role } });
    }

    // Verifica duplicidade de email
    pool.query('SELECT id FROM usuarios WHERE email = ? AND id <> ?', [email, id], (err, rows) => {
        if (err) {
            console.error(err);
            erros.push({ msg: 'Erro no servidor.' });
            return res.render('edit-usuario', { user: req.user, erros, usuario: { id, email, role } });
        }
        if (rows.length) {
            erros.push({ msg: 'E-mail já em uso.' });
            return res.render('edit-usuario', { user: req.user, erros, usuario: { id, email, role } });
        }

        // Atualiza
        pool.query(
            'UPDATE usuarios SET email = ?, role = ? WHERE id = ?',
            [email, role, id],
            updateErr => {
                if (updateErr) {
                    console.error(updateErr);
                    erros.push({ msg: 'Erro ao atualizar.' });
                    return res.render('edit-usuario', { user: req.user, erros, usuario: { id, email, role } });
                }
                res.redirect('/usuarios');
            }
        );
    });
});




// === EDITAR MOTORISTA ===

//const methodOverride = require('method-override');
//app.use(methodOverride('_method'));

//  exibe formulário com todos os campos
app.get('/motoristas/:id/edit', isAuthenticated, csrfProtection, (req, res) => {
    const { id } = req.params;
    pool.query('SELECT * FROM motoristas WHERE id = ?', [id], (err, results) => {
        if (err || !results.length) {
            return res.redirect('/motoristas');
        }
        res.render('edit-motorista', {
            user: req.user,
            csrfToken: req.csrfToken(),
            erros: [],
            motorista: results[0]
        });
    });
});


const uploadFoto = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (!file.mimetype.startsWith('image/')) {
            return cb(new Error('Só imagens são permitidas'), false);
        }
        cb(null, true);
    }
}).single('foto');



app.post('/api/editar-motorista/:id', isAuthenticated, uploadFoto, csrfProtection, (req, res) => {
    const { id } = req.params;
    const { nome, cpf, cnh, dataValidade, categoria } = req.body;
    const foto = req.file ? req.file.filename : null;
    const email = req.user.email;

    // validações 
    if (!nome || !cpf || !cnh || !dataValidade || !categoria)
        return res.status(400).json({ success: false, message: 'Preencha todos os campos.' });
    if (moment(dataValidade).isBefore(moment(), 'day'))
        return res.status(400).json({ success: false, message: 'CNH vencida.' });
    if (!validarCPF(cpf))
        return res.status(400).json({ success: false, message: 'CPF inválido.' });
    if (!/^[0-9]{11}$/.test(cnh.replace(/\D/g, '')))
        return res.status(400).json({ success: false, message: 'CNH inválida.' });

    // duplicidade cpf
    db.query('SELECT id FROM motoristas WHERE cpf=? AND id<>?', [cpf, id], (e, cpfRes) => {
        if (e) return res.status(500).json({ success: false, message: 'Erro ao verificar CPF.' });
        if (cpfRes.length) return res.status(400).json({ success: false, message: 'CPF já cadastrado.' });

        // duplicidade cnh
        db.query('SELECT id FROM motoristas WHERE cnh=? AND id<>?', [cnh, id], (e2, cnhRes) => {
            if (e2) return res.status(500).json({ success: false, message: 'Erro ao verificar CNH.' });
            if (cnhRes.length) return res.status(400).json({ success: false, message: 'CNH já cadastrada.' });

            // update
            const fields = [nome, email, cpf, cnh, dataValidade, categoria];
            let sql = 'UPDATE motoristas SET nome=?,email=?,cpf=?,cnh=?,data_validade=?,categoria=?';
            if (foto) { sql += ',foto=?'; fields.push(foto); }
            sql += ' WHERE id=?'; fields.push(id);
            db.query(sql, fields, (err) => {
                if (err) return res.status(500).json({ success: false, message: 'Erro ao atualizar.' });
                res.json({ success: true, message: 'Motorista atualizado!' });
            });
        });
    });
});


//////////////////////////////////fim editar ususarios e motoristas
// Socket.IO: conexão com o cliente
io.on("connection", (socket) => {
    console.log("Cliente conectado via Socket.IO.");
});
/*
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

*/

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

