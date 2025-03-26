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

// Configura o servidor HTTP e integra o Socket.IO
const http = require('http');
const app = express();
const server = http.createServer(app);
const { Server } = require('socket.io');
const io = new Server(server);

const port = 3000;


// Se a pasta 'uploads' não existir, cria ela
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// Configura a conexão com o banco de dados
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});
function connectToDatabase() {
    db.connect((err) => {
        if (err) {
            console.error('Erro ao conectar no DB:', err);
            console.log('Tentando reconectar em 5 seg...');
            setTimeout(connectToDatabase, 5000);
        } else {
            console.log('Conectado ao DB!');
            // Só liga o server depois de conectar no DB
            const PORT = process.env.PORT || 3000;
            app.listen(PORT, () => {
                console.log(`App rodando na porta ${PORT}`);
            });
        }
    });
}
connectToDatabase();

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
app.use(passport.initialize());
app.use(passport.session());

// Configura a estratégia local do Passport
passport.use(new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
    db.query("SELECT * FROM usuarios WHERE email = ?", [email], (err, results) => {
        if (err) return done(err);
        if (results.length === 0) return done(null, false, { message: 'Usuário não encontrado.' });
        const user = results[0];
        bcrypt.compare(password, user.senha, (err, isMatch) => {
            if (err) return done(err);
            if (isMatch) return done(null, user);
            return done(null, false, { message: 'Senha incorreta.' });
        });
    });
}));
passport.serializeUser((user, done) => {
    done(null, user.id);
});
passport.deserializeUser((id, done) => {
    db.query("SELECT * FROM usuarios WHERE id = ?", [id], (err, results) => {
        if (err) return done(err);
        done(null, results[0]);
    });
});
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
}

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

/* Rotas de autenticação */

// injetar active page global caso nao tenha 

app.use((req, res, next) => {
    res.locals.activePage = res.locals.activePage || '';
    next();
  });
  

app.get('/', isAuthenticated, (req, res) => {
    // Busca os veículos cadastrados
    db.query('SELECT * FROM veiculos', (err, results) => {
        if (err) throw err;
        // Conta os veículos
        db.query('SELECT COUNT(*) AS totalVeiculos FROM veiculos', (err, veiculosResult) => {
            if (err) throw err;
            // Conta as multas
            db.query('SELECT COUNT(*) AS totalMultas FROM multas', (err, multasResult) => {
                if (err) throw err;
                // Conta os registros de uso
                db.query('SELECT COUNT(*) AS totalUso FROM uso_veiculos', (err, usoResult) => {
                    if (err) throw err;
                    // Conta motoristas ativos (distintos)
                    db.query('SELECT COUNT(DISTINCT motorista) AS totalMotoristasAtivos FROM uso_veiculos', (err, motoristasResult) => {
                        if (err) throw err;
                        res.render('dashboard', {
                            title: 'Dashboard',
                            layout: 'layout', // Define o layout a ser usado (layout.ejs)
                            activePage: 'dashboard', // Página ativa para destaque no menu
                            veiculos: results,
                            user: req.user,
                            totalVeiculos: veiculosResult[0].totalVeiculos,
                            totalMultas: multasResult[0].totalMultas,
                            totalUso: usoResult[0].totalUso,
                            totalMotoristasAtivos: motoristasResult[0].totalMotoristasAtivos
                        });
                    });
                });
            });
        });
    });
});

// Tela de registro (só admin pode acessar)
app.get('/register', isAdmin, (req, res) => {
    res.render('register');
});

// Tela de login
app.get('/login', (req, res) => {
    res.render('login', { layout: 'login' }); //  layout exclusivo para login
});


// Faz o login
app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login'
}));

// Faz o logout e destrói a sessão
app.get('/logout', async (req, res, next) => {
    try {
        req.logout((err) => {
            if (err) return next(err);
            req.session.destroy(() => {
                res.redirect('/login');
            });
        });
    } catch (error) {
        console.error('Erro no logout:', error);
        res.redirect('/');
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



app.get('/perfil', isAuthenticated, (req, res) => {
    res.render('perfil', { user: req.user });
});
app.get('/index2', isAuthenticated, (req, res) => {
    res.render('index2', { user: req.user });
});

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
    let draw = req.query.draw;
    let start = parseInt(req.query.start) || 0;
    let length = parseInt(req.query.length) || 10;
    let searchValue = req.query.search ? req.query.search.value : '';

    // Parâmetros de ordenação
    let orderColumnIndex = req.query.order ? parseInt(req.query.order[0].column) : 0;
    let orderDir = req.query.order ? req.query.order[0].dir : 'asc';

    // Mapeia os índices para as colunas do banco
    let columns = ['veiculos.placa', 'motorista', 'km_inicial', 'km_final', 'data_hora_inicial', 'data_hora_final', 'data_criacao'];
    let orderColumn = columns[orderColumnIndex] || 'data_hora_inicial';

    // Monta a cláusula WHERE se tiver busca
    let whereClause = '';
    let params = [];
    if (searchValue) {
        whereClause = `WHERE (veiculos.placa LIKE ? OR motorista LIKE ? OR km_inicial LIKE ? OR km_final LIKE ? )`;
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

    params.push(length, start);

    db.query(sql, params, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Erro na consulta");
        }
        let countSql = `SELECT COUNT(DISTINCT uso_veiculos.id) AS total FROM uso_veiculos
                      JOIN veiculos ON uso_veiculos.veiculo_id = veiculos.id
                      LEFT JOIN multas ON uso_veiculos.id = multas.uso_id
                      ${whereClause}`;
        db.query(countSql, params.slice(0, whereClause ? 4 : 0), (err, countResult) => {
            if (err) {
                console.error(err);
                return res.status(500).send("Erro na consulta de contagem");
            }
            let totalRecords = countResult[0].total;

            // Total de registros sem filtro
            db.query('SELECT COUNT(*) AS total FROM uso_veiculos', (err, totalResult) => {
                if (err) {
                    console.error(err);
                    return res.status(500).send("Erro na consulta de contagem total");
                }
                let totalRecordsUnfiltered = totalResult[0].total;
                res.json({
                    draw: draw,
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
        activePage: 'registrar-veiculo' 
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


app.post('/registrar-multa/:veiculo_id', isAuthenticated, (req, res) => {
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
        // Pega o último uso com km_final preenchido pra definir o km_inicial
        db.query(
            'SELECT km_final FROM uso_veiculos WHERE veiculo_id = ? AND km_final IS NOT NULL ORDER BY id DESC LIMIT 1',
            [id],
            (err, usoResult) => {
                if (err) {
                    console.error("Erro ao buscar último uso:", err);
                    return res.status(500).send("Erro ao buscar o último uso.");
                }
                const kmInicial = usoResult.length > 0 ? usoResult[0].km_final : (veiculo.km || 0);
                res.render('usar', {
                    veiculo,
                    kmInicial,
                    title: 'Usar Veículo',
                    layout: 'layout',
                    activePage: 'usar'
                    
                });
            }
        );
    });
});

app.post('/usar/:id', isAuthenticated, upload.single('foto_km'), (req, res) => {
    const { id } = req.params; // ID do veículo
    const { motorista, km_inicial, km_final, data_hora_inicial, data_hora_final } = req.body;
    const foto_km = req.file ? req.file.filename : null;

    if (!motorista || !km_inicial) {
        return res.status(400).send('Campos obrigatórios faltando');
    }

    // Primeiro, busca os dados do veículo
    db.query('SELECT * FROM veiculos WHERE id = ?', [id], (err, veiculoResult) => {
        if (err) {
            console.error("Erro ao buscar veículo:", err);
            return res.status(500).send("Erro ao buscar o veículo.");
        }
        if (veiculoResult.length === 0) {
            return res.status(404).send("Veículo não encontrado");
        }
        const veiculo = veiculoResult[0];

        // Depois, pega o último uso pra definir o km_inicial esperado
        db.query(
            'SELECT km_final FROM uso_veiculos WHERE veiculo_id = ? AND km_final IS NOT NULL ORDER BY data_hora_inicial DESC LIMIT 1',
            [id],
            (err, usoResult) => {
                if (err) {
                    console.error("Erro ao buscar último uso:", err);
                    return res.status(500).send("Erro ao buscar o último uso.");
                }
                const expectedKmInicial = usoResult.length > 0 ? usoResult[0].km_final : veiculo.km;
                const kmInicialParsed = parseInt(km_inicial, 10);

                if (kmInicialParsed !== expectedKmInicial) {
                    return res.status(400).send("Erro: O km inicial deve ser igual ao km final do último uso ou ao km atual do veículo.");
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

                /* 
                  Checa se já existe um uso que se sobrepõe ao novo.
                  Verifica se:
                    - Uso existente começa antes do final do novo uso
                    - E se termina depois do início do novo uso (ou ainda tá rolando)
                */
                db.query(
                    `SELECT * FROM uso_veiculos 
                     WHERE (veiculo_id = ? OR motorista = ?)
                       AND (data_hora_inicial < ?)
                       AND ((data_hora_final IS NULL) OR (data_hora_final > ?))`,
                    [id, motorista, newEnd, dataHoraInicial],
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
                            [id, motorista, km_inicial, kmFinalValue, dataHoraInicial, dataHoraFinal, foto_km],
                            (err, result) => {
                                if (err) throw err;

                                // Se tiver km_final, atualiza o km do veículo e checa a troca de óleo
                                if (kmFinalValue !== null) {
                                    db.query('UPDATE veiculos SET km = ? WHERE id = ?', [kmFinalValue, id], (err, result2) => {
                                        if (err) {
                                            console.error("Erro ao atualizar km:", err);
                                        } else {
                                            console.log(`Veículo ${id} atualizado pra km=${kmFinalValue}`);
                                            checkOilChangeForVehicle(id);
                                        }
                                    });
                                }
                                res.redirect('/');
                            }
                        );
                    }
                );
            }
        );
    });
});

// Rota pra editar uso, atualizar multas e imagem
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

    // Se tem km_final ou data_hora_final, valida os valores
    if ((km_final && km_final !== '') || (data_hora_final && data_hora_final !== '')) {
        db.query("SELECT km_inicial, data_hora_inicial FROM uso_veiculos WHERE id = ?", [id], (err, resultSelect) => {
            if (err) {
                console.error("Erro na verificação:", err);
                return res.status(500).send("Erro interno");
            }
            if (resultSelect.length > 0) {
                const kmInicialValue = parseInt(resultSelect[0].km_inicial, 10);
                if (km_final && km_final !== '') {
                    const kmFinalParsed = parseInt(km_final, 10);
                    if (isNaN(kmFinalParsed)) {
                        return res.status(400).send('km_final inválido');
                    }
                    if (kmFinalParsed < kmInicialValue) {
                        return res.status(400).send('km final não pode ser menor que km inicial');
                    }
                    // km_final não pode ultrapassar a autonomia de um tanque 
                    const autonomiaUno = 500;
                    if ((kmFinalParsed - kmInicialValue) > autonomiaUno) {
                        return res.status(400).send(`O consumo excede a autonomia máxima de um tanque  (${autonomiaUno} km).`);
                    }
                }
                if (data_hora_final && data_hora_final !== '') {
                    const dataHoraFinalParsed = new Date(data_hora_final);
                    const dataHoraInicialParsed = new Date(resultSelect[0].data_hora_inicial);
                    if (dataHoraFinalParsed < dataHoraInicialParsed) {
                        return res.status(400).send('A data final não pode ser antes da inicial');
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
                return res.status(500).send('Erro ao atualizar uso');
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

            // Se tiver km_final, atualiza o km do veículo
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
                                    console.log(`Veículo ${veiculo_id} atualizado pra km=${kmFinalValue} via edição.`);
                                    checkOilChangeForVehicle(veiculo_id);
                                }
                            });
                        }
                    });
                }
            }

            if (novasMultas.length === 0) {
                return res.redirect('/relatorio-uso');
            }

            db.query("SELECT veiculo_id FROM uso_veiculos WHERE id = ?", [id], (err, result4) => {
                if (err) {
                    console.error("Erro ao buscar veículo:", err);
                    return res.status(500).send("Erro ao buscar veículo.");
                }
                if (result4.length === 0) {
                    return res.status(404).send("Veículo não encontrado para este uso.");
                }
                const veiculo_id = result4[0].veiculo_id;
                const valores = novasMultas.map(multa => [id, veiculo_id, multa.trim()]);
                db.query("INSERT INTO multas (uso_id, veiculo_id, multa) VALUES ?", [valores], (err) => {
                    if (err) {
                        console.error("Erro ao registrar novas multas:", err);
                        return res.status(500).send("Erro ao registrar novas multas.");
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

// Rota pra atualizar dados do veículo
app.post('/editar-veiculo/:id', isAuthenticated, isAdmin, (req, res) => {
    const id = req.params.id;
    const { nome, placa, km, ultimaTrocaOleo, modelo } = req.body;
    db.query(
        "UPDATE veiculos SET nome = ?, placa = ?, km = ?, ultimaTrocaOleo = ?, modelo = ? WHERE id = ?",
        [nome, placa, km, ultimaTrocaOleo, modelo, id],
        (err) => {
            if (err) {
                return res.status(500).send("Erro ao atualizar veículo.");
            }
            res.redirect('/');
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

// Rota de notificações: mostra veículos que precisam trocar óleo
app.get('/notificacoes', isAuthenticated, (req, res) => {
    const query = `
      SELECT *, (km - ultimaTrocaOleo) AS kmDesdeUltimaTroca 
      FROM veiculos 
      WHERE (km - ultimaTrocaOleo) >= 10000
    `;
    db.query(query, (err, results) => {
        if (err) {
            console.error("Erro ao buscar notificações:", err);
            return res.status(500).send("Erro no servidor");
        }
        res.render('notificacoes', {
            veiculos: results,
            title: 'Notificações',
            layout: 'layout',
            activePage: 'notificacoes'
        });

    });
});

// Socket.IO: conexão com o cliente
io.on("connection", (socket) => {
    console.log("Cliente conectado via Socket.IO.");
});

// GPS - Configura CORS e rota pra atualizar localização
const cors = require('cors');
app.use(cors({ origin: 'https://rococo-kangaroo-21ce36.netlify.app' }));
app.post('/update-location', (req, res) => {
    const { vehicleId, latitude, longitude } = req.body;
    console.log(`Veículo ${vehicleId}: Latitude ${latitude}, Longitude ${longitude}`);
    res.json({ status: 'ok', received: req.body });
});

// Rotas pra servir o manifest e o service worker (PWA)
app.get('/manifest.json', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'manifest.json'));
});

app.get('/service-worker.js', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'service-worker.js'));
});

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
