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

// Setup automático do banco em produção (Railway) - CARGA INICIAL AUTOMÁTICA
if (process.env.NODE_ENV === 'production') {
  const { seedDatabase } = require('./seed-database');
  seedDatabase().then(() => {
    console.log('✅ Banco pronto. Iniciando servidor...');
    startServer();
  }).catch(err => {
    console.error('❌ Falha na carga inicial do banco:', err);
    // Não fecha o app - tenta iniciar mesmo assim
    console.log('⚠️ Iniciando servidor mesmo sem carga inicial...');
    startServer();
  });
} else {
  startServer();
}

function startServer() {
  //time zone
  process.env.TZ = 'America/Sao_Paulo';
  // servidor HTTP  , Socket.IO
  const https = require('https');

  const app = express();

  // Railway/Heroku-style proxies terminate TLS before the app.
  // This allows secure cookies to work when the external connection is HTTPS.
  app.set('trust proxy', 1);

  let server;

  const HTTPS_ENABLED = process.env.HTTPS_ENABLED === 'true';

  if (HTTPS_ENABLED) {
    const sslKeyPath = process.env.SSL_KEY_PATH || '/certs/privkey.pem';
    const sslCertPath = process.env.SSL_CERT_PATH || '/certs/fullchain.pem';

    try {
      const privateKey = fs.readFileSync(sslKeyPath, 'utf8');
      const certificate = fs.readFileSync(sslCertPath, 'utf8');

      const credentials = { key: privateKey, cert: certificate };

      const https = require('https');
      server = https.createServer(credentials, app);

      console.log("Servidor HTTPS configurado.");
    } catch (err) {
      const http = require('http');
      server = http.createServer(app);
      console.warn(
        `Falha ao configurar HTTPS (certificados não encontrados ou inválidos). Iniciando em HTTP. Erro: ${err.message}`
      );
    }
  } else {
    const http = require('http');
    server = http.createServer(app);

    console.log("Servidor HTTP configurado.");
  }

  const { Server } = require('socket.io');

  const TRUSTED_ORIGINS = ["*"];
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
    port: process.env.DB_PORT ? Number(process.env.DB_PORT) : undefined,
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
server.listen(PORT, '0.0.0.0', () => {
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
    proxy: isProduction,
    secret: process.env.SECRET_SESSION,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 30 * 60 * 1000, // 30 minutos
      secure: isProduction ? true : HTTPS_ENABLED, // Em produção (Railway) roda atrás de proxy HTTPS
      httpOnly: true,
      sameSite: isProduction ? 'none' : (HTTPS_ENABLED ? 'none' : 'lax')
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
    max: 100,                  // até 10 tentativas
    message: "Muitas tentativas, aguarde 15 minutos."
});

app.use('/login', authLimiter);
app.use('/forgot-password', authLimiter);


// Body-parsers e sanitização
const { body, validationResult } = require('express-validator');
const validator = require('validator');

//app.use(multer().none());
// CSRF - DESABILITADO TEMPORARIAMENTE PARA DEPLOY
// const csurf = require('csurf');
// const csrfProtection = csurf();
// app.use(csrfProtection);
/* Em todas as views, expor req.csrfToken()
app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    next();
});*/

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

// middleware de auditoria
app.use(async (req, res, next) => {
    try {
      
      if (!req.path.startsWith('/public') && req.user) {
        const usuario = req.user.email;
        const rota    = req.originalUrl;
        const metodo  = req.method;
        // detalhes do body/query:
        const detalhes = JSON.stringify({ body: req.body, query: req.query });
        await query(
          'INSERT INTO auditoria (usuario, rota, metodo, detalhes) VALUES (?, ?, ?, ?)',
          [usuario, rota, metodo, detalhes]
        );
      }
    } catch (err) {
      console.error('Erro ao gravar auditoria', err);
    }
    next();
  });


// Rota auditoria 
app.get(
  '/auditoria',
  isAuthenticated,
  isAdmin,
    async (req, res) => {
    try {
      const { usuario, data, rota, metodo } = req.query;
      const filtros = [];
      const valores = [];

      if (usuario) {
        filtros.push('usuario LIKE ?');
        valores.push(`%${usuario}%`);
      }
      if (data) {
        filtros.push('DATE(criado_em) = ?');
        valores.push(data);
      }
      if (rota) {
        filtros.push('rota LIKE ?');
        valores.push(`%${rota}%`);
      }
      if (metodo) {
        filtros.push('metodo = ?');
        valores.push(metodo);
      }

      const where = filtros.length
        ? 'WHERE ' + filtros.join(' AND ')
        : '';

      const logs = await query(
        `SELECT
           usuario,
           rota,
           metodo,
           detalhes,
           DATE_FORMAT(criado_em, "%d/%m/%Y %H:%i:%s") AS criado_em
         FROM auditoria
         ${where}
         ORDER BY criado_em DESC
         LIMIT 1000`,
        valores
      );

      res.render('auditoria', {
        logs,
        filtro: req.query,
        csrfToken: 'disabled',
        user: req.user,
        activePage: 'auditoria'
      });
    } catch (err) {
      console.error('Erro na rota /auditoria:', err);
      res.status(500).send('Erro ao carregar auditoria');
    }
  }
);
  
  
// GET /login — gera e envia o token para a view
app.get('/login',
        (req, res) => {
        res.render('login', {
            layout: 'login',
            csrfToken: req.csrfToken()    // passa o token aqui
        });
    }
);


// Tela de esqueci minha senha
app.get('/forgot-password', (req, res) => {
    res.render('forgot-password', { layout: 'forgot-password', csrfToken: req.csrfToken(), });
});
app.post('/forgot-password', authLimiter,  (req, res) => {
    const email = validator.normalizeEmail(req.body.email || '');
    if (!email) return res.status(400).send("Email é obrigatório.");


app.get('/reset-password/:token',  (req, res) => {
    const { token } = req.params;
    db.query("SELECT * FROM usuarios WHERE password_reset_token = ? AND password_reset_expires > ?", [token, Date.now()], (err, results) => {
        if (err) return res.status(500).send("Erro no servidor.");
        if (results.length === 0) return res.status(400).send("Token inválido ou expirado.");
        res.render('reset-password', { layout: 'reset-password', token, csrfToken: req.csrfToken(), });
    });
});


// Função para checar a força da senha
function validatePasswordStrength(password) {
                multas: multasResult,
                title: 'Editar Uso',
                layout: 'layout',
                activePage: 'editarUso',
                user: req.user,
                csrfToken: req.csrfToken(),
            });
        });
    });
);


                }
                const uso = results[0];
                res.render('editarUso', {
                    uso,
                    errorMessage: message,
                    csrfToken: req.csrfToken(),
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
app.post('/troca-feita/:id', isAuthenticated, isAdmin,  (req, res) => {
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
app.post('/excluir-multa/:id', isAuthenticated, isAdmin,  (req, res) => {
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
app.post('/excluir-uso/:id', isAuthenticated, isAdmin,  (req, res) => {
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

app.post('/excluir-multiplos-usos', isAuthenticated, isAdmin,  (req, res) => {
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
app.get('/editar-veiculo/:id', isAuthenticated,  (req, res) => {
    const id = req.params.id;
    db.query("SELECT * FROM veiculos WHERE id = ?", [id], (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).send("Veículo não encontrado.");
        }
        res.render('editar-veiculo', {
            veiculo: results[0],
            csrfToken: 'disabled',
            title: 'Editar Veículo',
            layout: 'layout',
            activePage: 'editar-veiculo',
            user: req.user // Passa o usuário autenticado para o template
        });
    });
});

// Rota para atualizar dados do veículo
app.post('/editar-veiculo/:id', isAuthenticated,  (req, res) => {
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
app.get('/notificacoes', isAuthenticated, isAdmin,  (req, res) => {
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
                csrfToken: 'disabled',
                kmNotifications: notifResults,
                title: 'Notificações',
                layout: 'layout',
                activePage: 'notificacoes',
                user: req.user // Passa o usuário autenticado para o template
            });
        });
    });
});

app.post('/excluir-notificacao-alteracao-km/:id', isAuthenticated, isAdmin,  async (req, res) => {
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

const storageBanco = multer.memoryStorage();

const uploadFotoBanco = multer({
  storage: storageBanco,           // <- aqui
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) {
      return cb(new Error('Só imagens são permitidas'));
    }
    cb(null, true);
  }
}).single('foto');


app.get('/registro-motorista', isAuthenticated,  async (req, res) => {
    try {
      // Busca dados do motorista pelo email
      const resultados = await query(
        'SELECT * FROM motoristas WHERE email = ?',
        [req.user.email]
      );
  
      const jaCadastrado = resultados.length > 0;
      let motorista = null;
      let fotoBase64 = null;
  
      if (jaCadastrado) {
        motorista = resultados[0];
        // Converte BLOB em base64 se existir
        if (motorista.foto_cnh) {
          fotoBase64 = Buffer.from(motorista.foto_cnh).toString('base64');
        }
      }
  
      res.render('registro-motorista', {
        activePage: 'registro-motorista',
        user: req.user,
        csrfToken: 'disabled',
        title: 'Cadastro de Motorista',
        layout: 'layout',
        isMotorista: jaCadastrado,
        motorista,
        fotoCNH: fotoBase64,   // passe pro EJS para exibir <img src="data:image/jpeg;base64,...">
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
app.post(
    '/api/cadastro-motorista',
    isAuthenticated,
    uploadFotoBanco,
        async (req, res) => {
      try {
        const { nome, cpf, cnh, dataValidade, categoria } = req.body;
        const bufferFoto = req.file ? req.file.buffer : null;
        const email = req.user.email;
  
        // 1) Validações
        if (!nome || !cpf || !cnh || !dataValidade || !categoria) {
          return res.status(400).json({ success: false, message: 'Preencha todos os campos.' });
        }
        if (moment(dataValidade).isBefore(moment(), 'day')) {
          return res.status(400).json({ success: false, message: 'CNH vencida. Cadastro não permitido.' });
        }
        if (!validarCPF(cpf)) {
          return res.status(400).json({ success: false, message: 'CPF inválido.' });
        }
  
        // 2) Verifica duplicidade de CPF
        const rowsCPF = await query(
          'SELECT id FROM motoristas WHERE cpf = ?',
          [cpf]
        );
        if (rowsCPF.length > 0) {
          return res.status(400).json({ success: false, message: 'CPF já cadastrado.' });
        }
  
        // 3) Insere novo motorista (com BLOB)
        const sql = `
          INSERT INTO motoristas
            (nome, email, cpf, cnh, data_validade, categoria, foto_cnh)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `;
        const params = [nome, email, cpf, cnh, dataValidade, categoria, bufferFoto];
        await query(sql, params);
  
        return res.status(200).json({ success: true, message: 'Motorista cadastrado com sucesso!' });
  
      } catch (err) {
        console.error('Erro ao cadastrar motorista:', err);
        return res.status(500).json({ success: false, message: 'Erro interno.' });
      }
    }
  );


  // servir foto cnh 
  // GET /api/motorista/:id/cnh
app.get(
    '/api/motorista/:id/cnh',
    isAuthenticated,
    isAdmin,
    async (req, res) => {
      try {
        const { id } = req.params;
        // busca apenas o campo foto_cnh
        const rows = await query(
          'SELECT foto_cnh FROM motoristas WHERE id = ?',
          [id]
        );
        if (!rows.length || !rows[0].foto_cnh) {
          return res.status(404).json({ success: false, message: 'CNH não encontrada.' });
        }
        const blob = rows[0].foto_cnh;
        // transforma em base64 e já coloca o prefixo data URI
        const base64 = `data:image/jpeg;base64,${Buffer.from(blob).toString('base64')}`;
        res.json({ success: true, fotoCNH: base64 });
      } catch (err) {
        console.error('Erro ao buscar CNH:', err);
        res.status(500).json({ success: false, message: 'Erro interno.' });
      }
    }
  );
  

// GET /motoristas/fotos-cnh  exibir pagina fotos cnh
app.get(
    '/motoristas/fotos-cnh',
    isAuthenticated,
    isAdmin,
        async (req, res) => {
      try {
        const motoristas = await query(
          `SELECT
             id,
             nome,
             cpf,
             cnh,
             data_validade,
             categoria,
             foto_cnh
           FROM motoristas
           ORDER BY nome`,
          []
        );
  
        // Renderiza o EJS fotosCnh.ejs
        res.render('fotosCnh', {
          motoristas,
          csrfToken: 'disabled',
          user: req.user
        });
      } catch (err) {
        console.error('Erro ao buscar motoristas para fotosCnh:', err);
        res.status(500).send('Erro interno ao carregar fotos de CNH.');
      }
    }
  );
  
  // DELETE /api/deletar-motorista/:id
app.delete(
    '/api/deletar-motorista/:id',
    isAuthenticated,
        async (req, res) => {
      try {
        const { id } = req.params;
        // verificar que o motorista existe antes de apagar
        const rows = await query(
          'SELECT id FROM motoristas WHERE id = ?',
          [id]
        );
        if (!rows.length) {
          return res.status(404).json({ success: false, message: 'Motorista não encontrado.' });
        }
  
        // apaga o motorista
        await query(
          'DELETE FROM motoristas WHERE id = ?',
          [id]
        );
        return res.json({ success: true, message: 'Motorista excluído com sucesso!' });
      } catch (err) {
        console.error('Erro ao excluir motorista:', err);
        return res.status(500).json({ success: false, message: 'Erro interno.' });
      }
    }
  );
  
  

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
app.get('/registrar-manutencao/:veiculo_id', isAuthenticated, isAdmin,  (req, res) => {
    const { veiculo_id } = req.params;
    db.query("SELECT * FROM veiculos WHERE id = ?", [veiculo_id], (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).send("Veículo não encontrado.");
        }
        const veiculo = results[0];
        res.render('registrar-manutencao', {
            title: 'Registrar Manutenção',
            csrfToken: 'disabled',
            layout: 'layout',
            activePage: 'manutencao',
            veiculo,
            tipos: ['Rodízio de Pneus', 'Troca de Pneus', 'Troca de Pastilhas', 'Troca de Discos de Freio']
        });
    });
});

// Rota para processar cadastro de manutenção
app.post('/registrar-manutencao/:veiculo_id', isAuthenticated, isAdmin,  (req, res) => {
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
app.get('/manutencoes', isAuthenticated,  (req, res) => {
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
            csrfToken: 'disabled',
            layout: 'layout',
            activePage: 'manutencoes',
            manutencoes: results,
            user: req.user // Passa o usuário autenticado para o template
        });
    });
});

// Rota para marcar uma manutenção como realizada
app.post('/manutencoes/realizada/:id', isAuthenticated, isAdmin,  (req, res) => {
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
app.post('/reembolsos', upload.single('comprovante'), isAuthenticated,  async (req, res) => {
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
app.get('/reembolsos', isAuthenticated,  async (req, res) => {
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
            csrfToken: 'disabled',
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


app.get('/relatorio-consumo', isAuthenticated,  async (req, res) => {
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
            csrfToken: 'disabled',
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

app.get('/search', isAuthenticated,  async (req, res) => {
  const q = (req.query.q || '').trim();

  //  o que a busca abrange, para exibir no front
  const searchInfo = [
    { name: 'Veículos', fields: ['id', 'nome', 'placa'] },
    { name: 'Usos de Veículos', fields: ['id', 'motorista', 'km_inicial', 'km_final'] },
    { name: 'Multas', fields: ['id', 'multa', 'motorista', 'email'] },
    { name: 'Motoristas', fields: ['id', 'nome', 'email'] },
  ];

  // Se não digitar nada, renderiza apenas a ajuda
  if (!q) {
    return res.render('searchResults', {
      q,
      results: {},
      user: req.user,
      csrfToken: 'disabled',
      searchInfo
    });
  }

  try {
    // Busca em Veículos
    const veiculos = await query(
      `SELECT id, nome, placa
       FROM veiculos
       WHERE id = ?
         OR nome LIKE ?
         OR placa LIKE ?`,
      [q, `%${q}%`, `%${q}%`]
    );

    // Busca em Usos de Veículos
    const usos = await query(
      `SELECT id, motorista, km_inicial, km_final
       FROM uso_veiculos
       WHERE id = ?
         OR motorista LIKE ?`,
      [q, `%${q}%`]
    );

    // Busca em Multas – com JOIN para trazer o email do motorista
    const multas = await query(
      `SELECT m.id,
              m.multa,
              m.motorista,
              mot.email
       FROM multas AS m
       LEFT JOIN motoristas AS mot
         ON mot.nome = m.motorista
       WHERE m.id = ?
         OR m.multa LIKE ?
         OR m.motorista LIKE ?
         OR mot.email LIKE ?`,
      [q, `%${q}%`, `%${q}%`, `%${q}%`]
    );

    // Busca em Motoristas
    const motoristas = await query(
      `SELECT id, nome, email
       FROM motoristas
       WHERE id = ?
         OR nome LIKE ?
         
         OR email LIKE ?`,
      [q, `%${q}%`, `%${q}%`, `%${q}%`]
    );

    const results = { veiculos, usos, multas, motoristas };

    res.render('searchResults', {
      q,
      results,
      user: req.user,
      csrfToken: 'disabled',
      searchInfo
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
app.get('/conserto-viavel', isAuthenticated,  async (req, res) => {
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
            csrfToken: 'disabled',
            registros,
            activePage: 'conserto-viavel',
        });
    } catch (err) {
        console.error('Erro ao buscar registros:', err);
        // render de erro:  inclui user
        res.render('conserto-viavel', {
            user: req.user,
            csrfToken: 'disabled',
            registros: [],
            activePage: 'conserto-viavel',
        });
    }
});


// --- ROTA POST /salvar-avaliacao ---
app.post('/salvar-avaliacao', isAuthenticated,  (req, res) => {
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

app.post('/conserto-viavel', isAuthenticated,  async (req, res) => {
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
            csrfToken: 'disabled',
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
app.get('/api/marcas', isAuthenticated,  async (req, res) => {
    try {
        const { data } = await axios.get(
            'https://parallelum.com.br/fipe/api/v1/carros/marcas'
        );
        res.json({ sucesso: true, marcas: data });
    } catch (error) {
        res.status(500).json({ sucesso: false, error: error.message });
    }
});


app.get('/api/modelos', isAuthenticated,  async (req, res) => {
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

app.get('/api/anos', isAuthenticated,  async (req, res) => {
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

app.post('/excluir-avaliacao/:id', isAuthenticated,  async (req, res) => {
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
app.get('/register', isAuthenticated, isAdmin,  (req, res) => {
    res.render('register', {
        erros: [],
        csrfToken: 'disabled',
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
app.post('/register', isAuthenticated, isAdmin,  (req, res) => {
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
            csrfToken: 'disabled',
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
                        csrfToken: 'disabled',
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
app.get('/usuarios', isAuthenticated,  (req, res) => {
    pool.query('SELECT id, email, role FROM usuarios ORDER BY id', (err, results) => {
        if (err) {
            console.error(err);
            return res.sendStatus(500);
        }
        res.render('usuarios', {
            user: req.user,
            csrfToken: 'disabled',
            usuarios: results,
            activePage: 'usuarios'
        });
    });
});

// LISTAR MOTORISTAS
app.get('/motoristas', isAuthenticated,  (req, res) => {
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
            csrfToken: 'disabled',
            motoristas: results,
            activePage: 'motoristas'
        });
    });
});

app.delete(
    '/api/deletar-motorista/:id',
    isAuthenticated,
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
app.get('/usuarios/:id/edit', isAuthenticated,  (req, res) => {
    const { id } = req.params;
    pool.query('SELECT id, email, role FROM usuarios WHERE id = ?', [id], (err, results) => {
        if (err || !results.length) {
            return res.redirect('/usuarios');
        }
        res.render('edit-usuario', {
            user: req.user,
            csrfToken: 'disabled',
            erros: [],
            usuario: results[0]
        });
    });
});

//  valida e atualiza email e role
app.post('/usuarios/:id/edit', isAuthenticated,  (req, res) => {
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

// exibe formulário com todos os campos, incluindo fotoCNH
app.get(
    '/motoristas/:id/edit',
    isAuthenticated,
        async (req, res) => {
      const { id } = req.params;
      try {
        const resultados = await query(
          'SELECT * FROM motoristas WHERE id = ?',
          [id]
        );
        if (!resultados.length) {
          return res.redirect('/motoristas');
        }
  
        const motorista = resultados[0];
        let fotoCNH = null;
        if (motorista.foto_cnh) {
          fotoCNH = Buffer
            .from(motorista.foto_cnh)
            .toString('base64');
        }
  
        res.render('edit-motorista', {
          user: req.user,
          csrfToken: 'disabled',
          erros: [],
          motorista,
          fotoCNH    
        });
  
      } catch (err) {
        console.error('Erro ao buscar motorista para edição:', err);
        res.redirect('/motoristas');
      }
    }
  );
  

  /*const uploadFotoBanco = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
      if (!file.mimetype.startsWith('image/')) {
        return cb(new Error('Só imagens são permitidas'), false);
      }
      cb(null, true);
    }
  }).single('foto');*/
  
  app.post(
    '/api/editar-motorista/:id',
    isAuthenticated,
    uploadFotoBanco,
        async (req, res) => {
      const { id } = req.params;
      const { nome, cpf, cnh, dataValidade, categoria } = req.body;
      const bufferFoto = req.file ? req.file.buffer : null;
      const email = req.user.email;
  
      // validações
      if (!nome || !cpf || !cnh || !dataValidade || !categoria) {
        return res.status(400).json({ success: false, message: 'Preencha todos os campos.' });
      }
      if (moment(dataValidade).isBefore(moment(), 'day')) {
        return res.status(400).json({ success: false, message: 'CNH vencida.' });
      }
      if (!validarCPF(cpf)) {
        return res.status(400).json({ success: false, message: 'CPF inválido.' });
      }
      if (!/^[0-9]{9}$/.test(cnh.replace(/\D/g, ''))) {
        return res.status(400).json({ success: false, message: 'CNH inválida.' });
      }
  
      try {
        // duplicidade CPF
        const existingCPF = await query(
          'SELECT id FROM motoristas WHERE cpf = ? AND id <> ?',
          [cpf, id]
        );
        if (existingCPF.length) {
          return res.status(400).json({ success: false, message: 'CPF já cadastrado.' });
        }
  
        // duplicidade CNH
        const existingCNH = await query(
          'SELECT id FROM motoristas WHERE cnh = ? AND id <> ?',
          [cnh, id]
        );
        if (existingCNH.length) {
          return res.status(400).json({ success: false, message: 'CNH já cadastrada.' });
        }
  
        // build do UPDATE
        const fields = [nome, email, cpf, cnh, dataValidade, categoria];
        let sql = 'UPDATE motoristas SET nome=?, email=?, cpf=?, cnh=?, data_validade=?, categoria=?';
  
        if (bufferFoto) {
          sql += ', foto_cnh = ?';
          fields.push(bufferFoto);
        }
  
        sql += ' WHERE id = ?';
        fields.push(id);
  
        await query(sql, fields);
        res.json({ success: true, message: 'Motorista atualizado!' });
  
      } catch (err) {
        console.error('Erro ao atualizar motorista:', err);
        res.status(500).json({ success: false, message: 'Erro interno.' });
      }
    }
  );
  


//////////////////////////////////fim editar ususarios e motoristas
// Socket.IO: conexão com o cliente
io.on("connection", (socket) => {
    console.log("Cliente conectado via Socket.IO.");
});
////-----------------GPS   --------------------------
const jwt = require('jsonwebtoken');
const deviceSecrets = {
  'DIEGO-DEVICE-001': process.env.DEVICE_SECRET
};

// ====== 1) Endpoint de autenticação do dispositivo ======
app.post('/auth-device', (req, res) => {
  const { deviceId, deviceSecret } = req.body;
  const expected = deviceSecrets[deviceId];

  if (!expected || expected !== deviceSecret) {
    return res.status(401).json({ error: 'Credenciais do dispositivo inválidas' });
  }

  // gera um JWT de 24h para o dispositivo
  const accessToken = jwt.sign(
    { deviceId },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );

  res.json({ accessToken });
});

// ====== 2) Middleware de validação do JWT de acesso ======
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];
  if (!token) 
    return res.status(401).json({ error: 'Token não fornecido' });

  jwt.verify(token, process.env.JWT_SECRET, (err, payload) => {
    if (err) 
      return res.status(403).json({ error: 'Token inválido ou expirado' });
    req.deviceId = payload.deviceId;
    next();
  });
}

// ====== 3) Rota protegida que recebe dados de GPS ======
app.post('/update-location', authenticateToken, (req, res) => {
  const { vehicleId, latitude, longitude } = req.body;

  // Emite via Socket.IO para todos inscritos
  io.emit('locationUpdate', { vehicleId, latitude, longitude });

  // Gera um token de operação para registro/auditoria
  const operationToken = jwt.sign(
    {
      deviceId: req.deviceId,
      vehicleId,
      latitude,
      longitude,
      ts: Date.now()
    },
    process.env.JWT_SECRET,
    // opcional: expiresIn: '1h'
  );

  res.json({
    status: 'ok',
    received: { vehicleId, latitude, longitude },
    operationToken
  });

  console.log(`GPS de ${req.deviceId}: veículo ${vehicleId} → ${latitude},${longitude}`);
});

// Endpoint temporário para carga inicial (só em produção)
if (process.env.NODE_ENV === 'production') {
  const { seedDatabase } = require('./seed-database');
  
  app.get('/seed-database', async (req, res) => {
    try {
      console.log('🌱 Executando carga inicial via endpoint...');
      await seedDatabase();
      res.json({ 
        success: true, 
        message: 'Carga inicial concluída com sucesso!',
        usuario: 'hugo.leonardo.jobs@gmail.com / Bento1617@'
      });
    } catch (err) {
      console.error('❌ Erro na carga inicial:', err);
      res.status(500).json({ 
        success: false, 
        error: err.message 
      });
    }
  });
}


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

// Fecha a função startServer
}

/*
// Código para iniciar o servidor com Socket.IO (opcional)
// server.listen(port, () => {
//     console.log(`Servidor rodando na porta ${port}`);
// });
*/

