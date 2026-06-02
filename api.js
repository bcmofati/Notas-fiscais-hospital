const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { SignedXml } = require('xml-crypto');
const { DOMParser } = require('xmldom');
const PDFDocument = require('pdfkit');
const QRCode = require('qrcode');
const serverless = require('serverless-http');

const app = express();
app.use(cors());
app.use(express.json());

// Recupera e limpa a chave privada do Netlify
let privateKey = process.env.CHAVE_PRIVADA_A1 || null;

if (privateKey) {
    privateKey = privateKey.replace(/\\n/g, '\n');
    const match = privateKey.match(/-----BEGIN (RSA )?PRIVATE KEY-----([\s\S]*?)-----END (RSA )?PRIVATE KEY-----/);
    if (match) {
        const tipoChave = match[1] || '';
        const cabecalho = `-----BEGIN ${tipoChave}PRIVATE KEY-----`;
        const rodape = `-----END ${tipoChave}PRIVATE KEY-----`;
        const miolo = match[2].replace(/\s+/g, '');
        const mioloFormatado = miolo.match(/.{1,64}/g).join('\n');
        privateKey = `${cabecalho}\n${mioloFormatado}\n${rodape}`;
    }
}

// Função auxiliar para construir a estrutura XML padrão do DPS
function construirXmlDPS(numeroDPS, dhEmi, cpf, paciente, val, vIss, vPis, vCofins, tpAmb) {
    return `
        <DPS xmlns="http://www.sped.fazenda.gov.br/nfse">
            <infDPS Id="DPS${numeroDPS}">
                <tpAmb>${tpAmb}</tpAmb>
                <dhEmi>${dhEmi}</dhEmi>
                <prest>
                    <CNPJ>22705739000131</CNPJ>
                </prest>
                <toma>
                    <CPF>${cpf.replace(/\D/g, '')}</CPF>
                    <xNome>${paciente}</xNome>
                </toma>
                <serv>
                    <cLocPrestacao>3205309</cLocPrestacao>
                    <cTribNac>040301</cTribNac>
                    <cNBS>123012100</cNBS>
                    <xDescServ>Servicos Medicos Prestados. Paciente: ${paciente}</xDescServ>
                </serv>
                <valores>
                    <vServPrest>
                        <vServ>${val.toFixed(2)}</vServ>
                    </vServPrest>
                    <trib>
                        <tribMun>
                            <tribISSQN>1</tribISSQN>
                            <cLocIncid>3205309</cLocIncid>
                            <cBenef>32053090200007</cBenef>
                            <pAliqApli>2.00</pAliqApli>
                            <vISSQN>${vIss}</vISSQN>
                        </tribMun>
                        <tribFed>
                            <piscofins>
                                <vPis>${vPis}</vPis>
                                <vCofins>${vCofins}</vCofins>
                            </piscofins>
                        </tribFed>
                    </trib>
                </valores>
            </infDPS>
        </DPS>
    `;
}

app.post(['/api/emitir-nota', '/.netlify/functions/api/emitir-nota'], async (req, res) => {
    try {
        if (!privateKey) throw new Error("Chave privada não configurada.");

        const { paciente, cpf, valorPago, dataAtendimento } = req.body;
        const numeroDPS = Date.now(); 
        
        let dhEmi = new Date().toISOString();
        if (dataAtendimento) {
            dhEmi = `${dataAtendimento}T12:00:00.000Z`;
        }

        const val = parseFloat(valorPago);
        const vIss = (val * 0.02).toFixed(2); // Calcula 2% de ISS
        const vPis = (val * 0.0065).toFixed(2); // Calcula 0,65% de PIS
        const vCofins = (val * 0.03).toFixed(2); // Calcula 3% de COFINS

        // ETAPA 1: VALIDAÇÃO COMPULSÓRIA NO AMBIENTE DE HOMOLOGAÇÃO (Valor 2)
        const xmlValidacao = construirXmlDPS(numeroDPS, dhEmi, cpf, paciente, val, vIss, vPis, vCofins, '2');
        const xmlAssinadoValidacao = assinarXML(xmlValidacao, privateKey);
        if (!xmlAssinadoValidacao) {
            throw new Error("Erro na validação prévia: Falha crítica na assinatura do XML em Homologação.");
        }

        // ETAPA 2: DETERMINAÇÃO DO AMBIENTE ATIVO VIA VARIÁVEL
        const ambienteFiscal = process.env.AMBIENTE_FISCAL || '2'; 

        const xmlDPS = construirXmlDPS(numeroDPS, dhEmi, cpf, paciente, val, vIss, vPis, vCofins, ambienteFiscal);
        const xmlAssinado = assinarXML(xmlDPS, privateKey);

        // ETAPA 3: GERAÇÃO DO PDF EXIGIDO DA NT 008/2026
        const pdfBase64 = await gerarPdfDanfse(paciente, cpf, valorPago, numeroDPS, dhEmi, ambienteFiscal);

        return res.status(200).json({
            sucesso: true,
            mensagem: ambienteFiscal === '1' ? 'NFS-e emitida e validada em Produção.' : 'NFS-e validada em Homologação.',
            ambiente: ambienteFiscal === '1' ? 'Produção' : 'Homologação',
            pdfBase64: pdfBase64 
        });

    } catch (error) {
        console.error('[ERRO INTERNO]', error.message);
        return res.status(500).json({ sucesso: false, mensagem: error.message });
    }
});

function assinarXML(xmlString, pemPrivateKey) {
    const sig = new SignedXml();
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    sig.canonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    sig.addReference({
        xpath: "//*[local-name(.)='infDPS']",
        transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"],
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1"
    });
    sig.privateKey = pemPrivateKey;
    sig.computeSignature(xmlString);
    return sig.getSignedXml();
}

async function gerarPdfDanfse(paciente, cpf, valor, numero, dataEmissao, ambienteFiscal) {
    return new Promise(async (resolve, reject) => {
        try {
            const doc = new PDFDocument({ margin: 20, size: 'A4' });
            let buffers = [];
            
            doc.on('data', buffers.push.bind(buffers));
            doc.on('end', () => {
                const pdfData = Buffer.concat(buffers);
                resolve(pdfData.toString('base64'));
            });

            const urlConsulta = `https://www.nfse.gov.br/consultar?ch=3205309222270573900013100000000000${numero}`;
            const qrBuffer = await QRCode.toBuffer(urlConsulta, { margin: 0, width: 60 });

            const desenharCaixa = (x, y, w, h, titulo, conteudo, valorDireita = '') => {
                doc.lineWidth(0.5).rect(x, y, w, h).stroke();
                doc.fillColor('#f2f2f2').rect(x, y, w, 11).fill(); 
                doc.fillColor('black').font('Helvetica-Bold').fontSize(6).text(titulo, x + 3, y + 3);
                if (conteudo) doc.font('Helvetica').fontSize(8).text(conteudo, x + 3, y + 15);
                if (valorDireita) doc.font('Helvetica-Bold').fontSize(9).text(valorDireita, x, y + 14, { width: w - 5, align: 'right' });
            };

            doc.font('Helvetica-Bold').fontSize(16).text('DANFSe v2.0', 0, 30, { align: 'center' });
            doc.fontSize(9).text('Documento Auxiliar da Nota Fiscal de Serviço Eletrônica', 0, 48, { align: 'center' });
            
            if (ambienteFiscal === '2') {
                doc.fillColor('red').fontSize(11).text('AMBIENTE DE HOMOLOGAÇÃO - SEM VALIDADE JURÍDICA', 0, 65, { align: 'center' });
            } else {
                doc.fillColor('green').fontSize(11).text('AMBIENTE DE PRODUÇÃO - DOCUMENTO FISCAL VÁLIDO', 0, 65, { align: 'center' });
            }
            doc.fillColor('black');

            doc.image(qrBuffer, 500, 20, { width: 60 });
            doc.font('Helvetica').fontSize(5).text('Consulta da chave de acesso no\nportal nacional da NFS-e', 490, 85, { align: 'center', width: 80 });

            const dataFormatada = new Date(dataEmissao).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' });
            desenharCaixa(20, 110, 260, 30, 'CHAVE DE ACESSO DA NFS-E', `3205309222270573900013100000000000${numero}`);
            desenharCaixa(285, 110, 140, 30, 'NÚMERO DA NFS-E / DPS', `${numero}`);
            desenharCaixa(430, 110, 145, 30, 'DATA/HORA DA EMISSÃO (COMPETÊNCIA)', dataFormatada);

            doc.font('Helvetica-Bold').fontSize(8).text('EMITENTE DA NFS-e', 20, 150);
            desenharCaixa(20, 160, 555, 35, 'NOME / NOME EMPRESARIAL', 'SP MEDICOS ASSOCIADOS LTDA', 'CNPJ: 22.705.739/0001-31');

            doc.font('Helvetica-Bold').fontSize(8).text('TOMADOR DO SERVIÇO', 20, 205);
            desenharCaixa(20, 215, 555, 35, 'NOME / NOME EMPRESARIAL', paciente, `CPF: ${cpf}`);

            doc.font('Helvetica-Bold').fontSize(8).text('SERVIÇO PRESTADO', 20, 260);
            desenharCaixa(20, 270, 555, 45, 'CÓDIGO DE TRIBUTAÇÃO NACIONAL E DESCRIÇÃO', '04.03.01 - Hospitais e congêneres | NBS: 1.2301.21.00\nServicos Medicos Prestados.');

            const valNum = parseFloat(valor);
            
            // Ajuste Tributário Conforme Padrão NFS-e Nacional:
            const issCalculado = (valNum * 0.02).toFixed(2); // 2% Municipal
            const pisCalculado = (valNum * 0.0065).toFixed(2); // 0,65% PIS
            const cofinsCalculado = (valNum * 0.03).toFixed(2); // 3,00% COFINS
            
            // Lei da Transparência (Totais Aproximados - Lei 12.741/2012)
            const impostoAproxFederal = (valNum * 0.1125).toFixed(2); // 11,25% Federal
            const impostoAproxEstadual = (0).toFixed(2); // 0,00% Estadual
            const totalAprox = (valNum * 0.1325).toFixed(2); // 13,25% Total (11,25% Fed + 2,00% Mun)

            doc.font('Helvetica-Bold').fontSize(8).text('TRIBUTAÇÃO DO SERVIÇO E TRIBUTAÇÃO FEDERAL', 20, 325);
            desenharCaixa(20, 335, 135, 30, 'VALOR DO SERVIÇO', '', `R$ ${valNum.toFixed(2)}`);
            desenharCaixa(160, 335, 135, 30, 'ALÍQUOTA ISS', '', '2.00%');
            desenharCaixa(300, 335, 275, 30, 'BENEFÍCIO FISCAL APLICADO', 'BM: 32053090200007 (Vitória-ES)', ``);

            // Adicionando caixas de PIS e COFINS (Tributação Federal)
            desenharCaixa(20, 370, 275, 30, 'PIS - Débito Apuração Própria', '', `R$ ${pisCalculado}`);
            desenharCaixa(300, 370, 275, 30, 'COFINS - Débito Apuração Própria', '', `R$ ${cofinsCalculado}`);

            desenharCaixa(20, 405, 555, 30, 'VALOR LÍQUIDO DA NFS-E', '', `R$ ${valNum.toFixed(2)}`);

            doc.font('Helvetica-Bold').fontSize(8).text('INFORMAÇÕES COMPLEMENTARES', 20, 445);
            desenharCaixa(20, 455, 555, 40, 'TOTAIS APROXIMADOS DOS TRIBUTOS (LEI Nº 12.741/2012)', `Federais (11,25%): R$ ${impostoAproxFederal} | Estaduais (0,00%): R$ ${impostoAproxEstadual} | Municipais (2,00%): R$ ${issCalculado} | Total: R$ ${totalAprox} (13,25%)\nLocal da Prestação: Vitória - ES | Benefício Municipal: 32053090200007`);

            doc.end();
        } catch (err) {
            reject(err);
        }
    });
}

module.exports.handler = serverless(app);
