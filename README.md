🚀 Assistente AIOps - Network Troubleshooting (V11.2)

O Assistente AIOps é uma ferramenta de automação com Inteligência Artificial projetada para Engenheiros de Redes (Nível 2 e Nível 3). Ele se conecta via SSH a equipamentos Huawei, extrai dados de roteamento ou logs, e utiliza a IA do Llama 3.1 (via Groq Cloud) para entregar a causa raiz de problemas em questão de segundos.



✨ Principais Funcionalidades

🤖 Análise com IA (Root Cause Analysis): Traduz logs complexos e tabelas de roteamento para uma linguagem direta, apontando o erro, a causa e o plano de ação.



🎯 Smart Filter (Deep Dive BGP): Lê dezenas de sessões BGP, filtra automaticamente quem está funcionando perfeitamente e executa comandos verbose apenas nos peers que estão com falha.



📸 Golden Config: Tira "fotos" do estado atual da rede para comparações futuras. A IA consegue ler o arquivo antigo e o novo e te dizer exatamente o que quebrou.



📊 Visualização em Abas: Separação limpa entre o Diagnóstico da IA, os Logs de Sistema (ações do script) e os Dados Brutos (o output real da CLI da Huawei).



💾 Banco de Dados Local: Salva automaticamente todo o histórico de diagnósticos em um arquivo .db (SQLite) invisível e super leve na mesma pasta.



🛠️ Módulos de Análise Suportados

BGP IPv4 / IPv6 (Resumo e Deep Dive): Análise de vizinhança BGP.



OSPF: Análise de adjacências e falhas de estabelecimento.



MPLS LDP: Verificação de sessões Operational.



Interfaces (Health Check): Auditoria física de portas buscando link down acidental, pacotes dropados, e erros de CRC.



Logs Avançados: Leitura focada das últimas 100 linhas de logbuffer e 30 linhas de trapbuffer.



⚙️ Como Instalar e Configurar

Esta ferramenta não requer instalação do Python na máquina do usuário final. Ela roda a partir de um executável portátil (.exe).



Passo 1: Extraia os arquivos para uma pasta no seu computador.

Passo 2: É obrigatório ter o arquivo .env na mesma pasta do arquivo .exe.

Passo 3: Abra o arquivo .env no Bloco de Notas e preencha com as suas credenciais. O arquivo deve ter exatamente este formato:



Snippet de código

GROQ\_API\_KEY=gsk\_sua\_chave\_gratuita\_do\_groq\_aqui

ROUTER\_IP=10.0.0.1

ROUTER\_USER=seu\_usuario\_ssh

ROUTER\_PASS=sua\_senha\_ssh

(Nota: O IP, usuário e senha no .env servem apenas para preencher a tela inicial e poupar tempo. Você pode alterá-los direto na interface gráfica se quiser testar outro equipamento).



🚀 Como Usar

Dê dois cliques no gui\_agent.exe.



Digite o IP do equipamento (ou clique em "Carregar Lista TXT" para analisar vários equipamentos em lote).



Selecione o Módulo de Análise desejado.



Clique em ⚡ Executar Análise Groq.



Navegue pelas abas:



🧠 Diagnóstico IA: Veja a resposta mastigada e o plano de ação.



⚙️ Logs do Sistema: Acompanhe em tempo real o que o script está fazendo (login, extração, filtro).



📄 Dados Brutos (CLI): Veja a saída original do roteador Huawei para auditoria manual.



(Opcional) Clique em 💾 Exportar TXT para salvar o laudo da IA e enviar para o cliente ou anexar ao chamado/ticket.



⚠️ Limitações de Segurança (Rate Limit)

Para manter a ferramenta 100% gratuita utilizando a API do Groq, o software possui "cintos de segurança" embutidos:



Execução em Fila: O script analisa 1 roteador por vez para não sobrecarregar as requisições.



Corte de Caracteres: Se um equipamento cuspir um log gigantesco, a ferramenta enviará apenas os últimos 10.000 caracteres (onde estão os erros mais recentes) para a IA, garantindo que o limite de Tokens da API não estoure.



Desenvolvido para automatizar o que é chato, para você focar no que é importante.

