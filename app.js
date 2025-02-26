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

// Criação do servidor HTTP e integração com Socket.IO
const http = require('http');
const app = express();
const server = http.createServer(app);
const { Server } = require('socket.io');
const io = new Server(server);

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

// Middleware de autorização para administradores
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

// Configuração do EJS e arquivos estáticos
app.set('view engine', 'ejs');
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
// Configuração de sessão e Passport
app.use(session({
    secret: process.env.SECRET_SESSION, 
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 60 * 1000 } // 30 minutos inativa
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

/* -------------------------
   FUNÇÕES DE NOTIFICAÇÃO
------------------------- */

// Função para enviar e-mail de notificação de troca de óleo
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
        text: `O veículo ${veiculo.nome} (Placa: ${veiculo.placa}) atingiu ${veiculo.km} km, com a última troca de óleo em ${veiculo.ultimaTrocaOleo}. Por favor, agende a manutenção necessária.`
    };
    transporter.sendMail(mailOptions, (err, info) => {
        if (err) console.error("Erro ao enviar e-mail de notificação:", err);
        else console.log("E-mail de notificação enviado:", info.response);
    });
}

function checkOilChangeForVehicle(veiculo_id) {
    const query = `SELECT * FROM veiculos WHERE id = ?`;
    db.query(query, [veiculo_id], (err, results) => {
      if (err) {
        console.error("Erro na verificação de troca de óleo:", err);
        return;
      }
      if (results.length > 0) {
        const veiculo = results[0];
        // Converte os valores para números
        const km = Number(veiculo.km);
        const ultimaTroca = Number(veiculo.ultimaTrocaOleo);
        console.log(`Verificando veículo ${veiculo.id}: km=${km}, ultimaTrocaOleo=${ultimaTroca}, diff=${km - ultimaTroca}`);
        
        // Se a diferença for maior ou igual a 10.000, dispara a notificação
        if ((km - ultimaTroca) >= 10000) {
          io.emit('oilChangeNotification', veiculo);
          sendOilChangeEmail(veiculo);
        }
      }
    });
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
                from: process.env.EMAIL_USER,
                subject: 'Redefinição de Senha',
                text: `Você está recebendo este e-mail porque foi solicitada a redefinição da senha da sua conta.\n\n` +
                      `Clique no link a seguir ou cole-o em seu navegador para redefinir sua senha:\n\n` +
                      `http://${req.headers.host}/reset-password/${token}\n\n` +
                      `Se você não solicitou a redefinição, ignore este e-mail.\n`
            };
            
            transporter.sendMail(mailOptions, (err) => {
                if (err) return res.status(500).send("Erro ao enviar e-mail.");
                res.send("Um e-mail foi enviado com instruções para redefinir sua senha.");
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
   ROTAS DE USO, VEÍCULOS, MULTAS, ETC.
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

// Rota para registrar o uso do veículo; ao finalizar, se km_final for informado, atualiza o veículo e verifica a necessidade de troca de óleo
app.post('/usar/:id', isAuthenticated, upload.single('foto_km'), (req, res) => {
    const { id } = req.params; // id do veículo
    const { motorista, km_inicial, km_final, multa, data_hora_final } = req.body;
    const data_hora_inicial = new Date();
    const foto_km = req.file ? req.file.filename : null;

    if (!motorista || !km_inicial) {
        return res.status(400).send('Há campos obrigatórios não preenchidos');
    }

    // Verifica e converte o km_final
    console.log("Valor km_final recebido do formulário:", km_final);
    const kmFinalParsed = parseInt(km_final, 10);
    const kmFinal = (km_final === '' || isNaN(kmFinalParsed)) ? null : kmFinalParsed;
    console.log("Após conversão, kmFinal:", kmFinal);

    const dataHoraFinal = data_hora_final ? new Date(data_hora_final) : null;

    // Insere o registro de uso
    db.query(
        'INSERT INTO uso_veiculos (veiculo_id, motorista, km_inicial, km_final, data_hora_inicial, data_hora_final, foto_km) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [id, motorista, km_inicial, kmFinal, data_hora_inicial, dataHoraFinal, foto_km],
        (err, result) => {
            if (err) throw err;

            // Se um km_final válido foi informado, atualiza a quilometragem do veículo
            if (kmFinal !== null) {
                db.query('UPDATE veiculos SET km = ? WHERE id = ?', [kmFinal, id], (err, result2) => {
                    if (err) {
                        console.error("Erro ao atualizar km do veículo:", err);
                    } else {
                        console.log(`Veículo ${id} atualizado para km=${kmFinal}`);
                        // Após atualizar, verifica se a diferença atinge ou ultrapassa 10.000 km para notificar troca de óleo
                        checkOilChangeForVehicle(id);
                    }
                });
            }
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
        }
    );
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

app.get('/editar-uso/:id', isAuthenticated, (req, res) => {
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

// Rota para editar uso, multas e atualizar imagem
app.post('/editar-uso/:id', isAuthenticated, uploadMultiple, (req, res) => {
    const { id } = req.params;
    const { motorista, km_final, data_hora_final, multas_id, multas_descricao } = req.body;
    const novasMultas = req.body.novasMultas 
        ? [].concat(req.body.novasMultas).filter(m => m.trim().length > 0)
        : [];

    // Verifica se foi enviado um novo arquivo para foto_km
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

        // Se um km_final foi informado na edição, atualiza a quilometragem do veículo
        if (km_final && km_final !== '') {
            const kmFinalParsed = parseInt(km_final, 10);
            const kmFinalValue = isNaN(kmFinalParsed) ? null : kmFinalParsed;
            if (kmFinalValue !== null) {
                // Primeiro, obtenha o veiculo_id associado a esse uso
                db.query("SELECT veiculo_id FROM uso_veiculos WHERE id = ?", [id], (err, result2) => {
                    if (err) {
                        console.error("Erro ao buscar veiculo_id para uso:", err);
                    } else if (result2.length > 0) {
                        const veiculo_id = result2[0].veiculo_id;
                        // Atualiza a quilometragem do veículo
                        db.query("UPDATE veiculos SET km = ? WHERE id = ?", [kmFinalValue, veiculo_id], (err, result3) => {
                            if (err) {
                                console.error("Erro ao atualizar km do veículo:", err);
                            } else {
                                console.log(`Veículo ${veiculo_id} atualizado para km=${kmFinalValue} via edição de uso.`);
                                // Verifica se o veículo precisa de troca de óleo
                                checkOilChangeForVehicle(veiculo_id);
                            }
                        });
                    }
                });
            }
        }

        // Se não houver novas multas para inserir, redireciona
        if (novasMultas.length === 0) {
            return res.redirect('/relatorio-uso');
        }

        // Insere as novas multas, se houver
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
});

// Rota para marcar que a troca de óleo foi realizada e atualizar ultimaTrocaOleo
app.post('/troca-feita/:id', isAuthenticated, isAdmin, (req, res) => {
    const { id } = req.params;
    // Atualiza o campo ultimaTrocaOleo com o valor atual de km do veículo
    db.query('UPDATE veiculos SET ultimaTrocaOleo = km WHERE id = ?', [id], (err, result) => {
       if (err) {
          console.error("Erro ao atualizar ultimaTrocaOleo:", err);
          return res.status(500).send("Erro ao atualizar troca de óleo.");
       }
       console.log(`Veículo ${id}: troca de óleo marcada. ultimaTrocaOleo atualizada para km atual.`);
       res.redirect('/notificacoes');
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
// Rota para exibir a página de edição do veículo
app.get('/editar-veiculo/:id', isAuthenticated, (req, res) => {
    const id = req.params.id;
    db.query("SELECT * FROM veiculos WHERE id = ?", [id], (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).send("Veículo não encontrado.");
        }
        res.render('editar-veiculo', { veiculo: results[0] });
    });
});

// Rota para atualizar os dados do veículo
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

app.post('/excluir-veiculo/:id', isAuthenticated, isAdmin, (req, res) => {
    const id = req.params.id;
    db.query("DELETE FROM veiculos WHERE id = ?", [id], (err) => {
        if (err) {
            return res.status(500).send("Erro ao excluir veículo.");
        }
        res.redirect('/');
    });
});

// Rota de notificações – exibe a página com os veículos que necessitam de troca de óleo
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
      res.render('notificacoes', { veiculos: results });
    });
});

// Socket.IO: registra a conexão com o cliente
io.on("connection", (socket) => {
    console.log("Cliente conectado via Socket.IO.");
});

// Inicia o servidor
server.listen(port, () => {
    console.log(`Servidor rodando na porta ${port}`);
});
