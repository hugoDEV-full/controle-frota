const express = require('express'); 
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

const app = express();
const port = 3000;

// Criação da pasta de uploads, se não existir
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// Conexão com o banco de dados
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect((err) => {
    if (err) throw err;
    console.log('Conectado ao banco de dados!');
});

// Após db.connect(...)
/*const adminEmail = 'aicrminova@gmail.com';
const adminPassword = 'Inova2024@*';
const adminRole = 'admin';

// Verifica se o usuário admin já existe
db.query("SELECT * FROM usuarios WHERE email = ?", [adminEmail], (err, results) => {
  if (err) {
    console.error("Erro ao verificar usuário admin:", err);
    return;
  }
  if (results.length === 0) {
    // Gera o hash da senha e insere o usuário administrador
    bcrypt.hash(adminPassword, 10, (err, hash) => {
      if (err) {
        console.error("Erro ao gerar hash da senha:", err);
        return;
      }
      db.query("INSERT INTO usuarios (email, senha, role) VALUES (?, ?, ?)",
        [adminEmail, hash, adminRole],
        (err, result) => {
          if (err) {
            console.error("Erro ao inserir usuário admin:", err);
          } else {
            console.log("Usuário admin criado com sucesso!");
          }
        }
      );
    });
  } else {
    console.log("Usuário admin já existe.");
  }
});
*/

function isAdmin(req, res, next) {
    if (req.isAuthenticated() && req.user.role === 'admin') {
      return next();
    }
    res.status(403).send("Acesso negado. Apenas administradores podem executar essa operação.");
}

// Configuração do multer para upload de imagens
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
    limits: { fileSize: 5 * 1024 * 1024 },
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
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Tipo de arquivo não permitido'), false);
        }
    }
}).array('foto_km');

// Configuração do EJS
app.set('view engine', 'ejs');
// serve os arquivos estáticos da pasta uploads com o prefixo '/uploads'
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Configuração de sessão e Passport
app.use(session({
    secret: process.env.SECRET_SESSION, // altere para uma chave segura
    resave: false,
    saveUninitialized: false,
    cookie: {
       maxAge: 30 * 60 * 1000 // 30 minutos
    }
}));
app.use(passport.initialize());
app.use(passport.session());

// Configuração do Passport Local Strategy
passport.use(new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
    db.query("SELECT * FROM usuarios WHERE email = ?", [email], (err, results) => {
        if (err) return done(err);
        if (results.length === 0) return done(null, false, { message: 'Usuário não encontrado.' });
        const user = results[0];
        bcrypt.compare(password, user.senha, (err, isMatch) => {
            if (err) return done(err);
            if (isMatch) {
                return done(null, user);
            } else {
                return done(null, false, { message: 'Senha incorreta.' });
            }
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

// Middleware para proteger rotas
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
}

/* -------------------------
   ROTAS DE AUTENTICAÇÃO
------------------------- */

app.get('/register', isAdmin, (req, res) => {
    res.render('register');
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login'
}));

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

app.get('/forgot-password', (req, res) => {
    res.render('forgot-password');
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
                from: 'seuemail@gmail.com',
                subject: 'Redefinição de Senha',
                text: `Você está recebendo este email porque foi solicitada a redefinição da senha da sua conta.\n\n` +
                      `Clique no link a seguir ou cole-o em seu navegador para redefinir sua senha:\n\n` +
                      `http://${req.headers.host}/reset-password/${token}\n\n` +
                      `Se você não solicitou a redefinição, ignore este email.\n`
            };
            
            transporter.sendMail(mailOptions, (err) => {
                if (err) return res.status(500).send("Erro ao enviar email.");
                res.send("Um email foi enviado com instruções para redefinir sua senha.");
            });
        });
    });
});

app.get('/reset-password/:token', (req, res) => {
    const { token } = req.params;
    db.query("SELECT * FROM usuarios WHERE password_reset_token = ? AND password_reset_expires > ?", [token, Date.now()], (err, results) => {
        if (err) return res.status(500).send("Erro no servidor.");
        if (results.length === 0) return res.status(400).send("Token inválido ou expirado.");
        res.render('reset-password', { token });
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
                res.send("Senha atualizada com sucesso. Você já pode fazer login.");
            });
        });
    });
});

/* -------------------------
   ROTAS PROTEGIDAS 
------------------------- */

app.get('/perfil', isAuthenticated, (req, res) => {
    res.render('perfil', { user: req.user });
});

/* -------------------------
   ROTAS EXISTENTES (USO, VEÍCULOS, MULTAS, ETC.)
   
------------------------- */

app.get('/usar/:id', isAuthenticated, (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM veiculos WHERE id = ?', [id], (err, results) => {
        if (err) {
            console.error('Erro ao buscar veículo:', err);
            return res.status(500).send('Erro ao buscar veículo');
        }
        if (results.length === 0) {
            return res.status(404).send('Veículo não encontrado');
        }
        res.render('usar', { veiculo: results[0] });
    });
});

app.post('/usar/:id', isAuthenticated, upload.single('foto_km'), (req, res) => {
    const { id } = req.params;
    const { motorista, km_inicial, km_final, multa, data_hora_final } = req.body;
    const data_hora_inicial = new Date();
    const foto_km = req.file ? req.file.filename : null;
    if (!motorista || !km_inicial) {
        return res.status(400).send('Há campos obrigatórios não preenchidos');
    }
    const kmFinal = km_final === '' ? null : km_final;
    const dataHoraFinal = data_hora_final ? new Date(data_hora_final) : null;
    db.query(
        'INSERT INTO uso_veiculos (veiculo_id, motorista, km_inicial, km_final, data_hora_inicial, data_hora_final, foto_km) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [id, motorista, km_inicial, kmFinal, data_hora_inicial, dataHoraFinal, foto_km],
        (err, result) => {
            if (err) throw err;
            res.redirect('/');
        }
    );
});

app.get('/relatorio-uso', isAuthenticated, (req, res) => {
    const page = req.query.page || 1;
    const pageSize = 10;
    const offset = (page - 1) * pageSize;
    db.query(
        `SELECT uso_veiculos.*, veiculos.placa, GROUP_CONCAT(multas.multa SEPARATOR ", ") AS multas
         FROM uso_veiculos
         JOIN veiculos ON uso_veiculos.veiculo_id = veiculos.id
         LEFT JOIN multas ON uso_veiculos.id = multas.uso_id
         GROUP BY uso_veiculos.id
         LIMIT ? OFFSET ?`,
        [pageSize, offset],
        (err, results) => {
            if (err) throw err;
            db.query('SELECT COUNT(*) AS total FROM uso_veiculos', (err, countResult) => {
                if (err) throw err;
                const totalPages = Math.ceil(countResult[0].total / pageSize);
                res.render('relatorio_uso', { usoVeiculos: results, totalPages, currentPage: page });
            });
        }
    );
});

app.get('/', isAuthenticated, (req, res) => {
    db.query('SELECT * FROM veiculos', (err, results) => {
        if (err) throw err;
        res.render('index', { veiculos: results, user: req.user });

    });
});

app.get('/registrar-veiculo', isAuthenticated, isAdmin, (req, res) => {
    res.render('registrar-veiculo');
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
        });
});

app.post('/multar/:uso_id', isAuthenticated, isAdmin, (req, res) => {
    const { uso_id } = req.params;
    let { multas } = req.body;
    if (typeof multas === 'string') {
        multas = [multas.trim()];
    } else if (Array.isArray(multas)) {
        multas = multas.map(m => m.trim()).filter(m => m.length > 0);
    }
    if (!multas || !Array.isArray(multas) || multas.length === 0) {
        return res.status(400).send('É necessário fornecer ao menos uma multa');
    }
    db.query("SELECT veiculo_id FROM uso_veiculos WHERE id = ?", [uso_id], (err, result) => {
        if (err) {
            console.error("Erro ao buscar veículo:", err);
            return res.status(500).send("Erro ao buscar veículo.");
        }
        if (result.length === 0) {
            return res.status(404).send("Nenhum veículo encontrado para este uso.");
        }
        const veiculo_id = result[0].veiculo_id;
        const sql = "INSERT INTO multas (uso_id, veiculo_id, multa) VALUES ?";
        const valores = multas.map(multa => [uso_id, veiculo_id, multa]);
        db.query(sql, [valores], (err, resultado) => {
            if (err) {
                console.error("Erro ao registrar multas:", err);
                return res.status(500).send("Erro ao registrar multas.");
            }
            console.log("Multas registradas com sucesso!");
            res.redirect('/relatorio-uso');
        });
    });
});

app.get('/editar-uso/:id', isAuthenticated,  (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM uso_veiculos WHERE id = ?', [id], (err, usoResult) => {
      if (err) {
        console.error('Erro ao buscar o uso do veículo:', err);
        return res.status(500).send('Erro ao buscar dados do uso do veículo');
      }
      if (usoResult.length === 0) {
        return res.status(404).send('Uso do veículo não encontrado');
      }
      const uso = usoResult[0];
      db.query('SELECT * FROM multas WHERE uso_id = ?', [id], (err, multasResult) => {
        if (err) {
          console.error('Erro ao buscar multas:', err);
          return res.status(500).send('Erro ao buscar multas');
        }
        res.render('editarUso', { uso, multas: multasResult });
      });
    });
});

// Rota para editar uso e multas e atualização de imagem
app.post('/editar-uso/:id', isAuthenticated, uploadMultiple, (req, res) => {
    const { id } = req.params;
    const { motorista, km_final, data_hora_final, multas_id, multas_descricao } = req.body;
    const novasMultas = req.body.novasMultas 
        ? [].concat(req.body.novasMultas).filter(m => m.trim().length > 0)
        : [];

    //console.log("Recebendo dados do formulário:", req.body);

    // Verifica se foi enviado um novo arquivo para foto_km
    let updateQuery, params;
    if (req.files && req.files.length > 0) {
        // Se houver nova imagem, atualiza também o campo foto_km
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
        // Se não houver nova imagem, atualiza somente os demais campos
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

    db.query(updateQuery, params, (err, result) => {
        if (err) {
            console.error("Erro ao atualizar uso do veículo:", err);
            return res.status(500).send('Erro ao atualizar uso do veículo');
        }

        // Atualiza as multas já existentes, se houver
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

        // Se não houver novas multas para inserir, redireciona
        if (novasMultas.length === 0) {
            return res.redirect('/relatorio-uso');
        }

        // Busca o veiculo_id para inserir as novas multas
        db.query("SELECT veiculo_id FROM uso_veiculos WHERE id = ?", [id], (err, result) => {
            if (err) {
                console.error("Erro ao buscar veículo:", err);
                return res.status(500).send("Erro ao buscar veículo.");
            }
            if (result.length === 0) {
                return res.status(404).send("Veículo não encontrado para este uso.");
            }

            const veiculo_id = result[0].veiculo_id;
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
});


// Rota para excluir uma multa
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

app.post('/excluir-uso/:id', isAuthenticated, isAdmin, (req, res) => {
    const { id } = req.params;
    db.query("DELETE FROM multas WHERE uso_id = ?", [id], (err, result) => {
      if (err) {
        console.error("Erro ao excluir multas:", err);
        return res.status(500).send("Erro ao excluir multas.");
      }
      db.query("DELETE FROM uso_veiculos WHERE id = ?", [id], (err, result) => {
        if (err) {
          console.error("Erro ao excluir o uso:", err);
          return res.status(500).send("Erro ao excluir o uso do veículo.");
        }
        res.redirect('/relatorio-uso');
      });
    });
});

app.get('/editar-veiculo/:id',isAuthenticated, (req, res) => {
    const id = req.params.id;
    db.query("SELECT * FROM veiculos WHERE id = ?", [id], (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).send("Veículo não encontrado.");
        }
        res.render('editar-veiculo', { veiculo: results[0] });
    });
});

app.post('/editar-veiculo/:id', isAuthenticated,isAdmin,(req, res) => {
    const id = req.params.id;
    const { nome, placa } = req.body;
    
    db.query("UPDATE veiculos SET nome = ?, placa = ? WHERE id = ?", [nome, placa, id], (err) => {
        if (err) {
            return res.status(500).send("Erro ao atualizar veículo.");
        }
        res.redirect('/');
    });
});

app.post('/excluir-veiculo/:id', isAuthenticated,isAdmin,(req, res) => {
    const id = req.params.id;
    db.query("DELETE FROM veiculos WHERE id = ?", [id], (err) => {
        if (err) {
            return res.status(500).send("Erro ao excluir veículo.");
        }
        res.redirect('/');
    });
});

app.listen(port, () => {
    console.log(`Servidor rodando na porta ${port}`);
});
