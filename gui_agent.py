import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from datetime import datetime
import concurrent.futures
import sqlite3
from dotenv import load_dotenv
from netmiko import ConnectHandler
from groq import Groq

# --- CONFIGURAÇÕES DE AMBIENTE E PASTAS ---
if getattr(sys, 'frozen', False):
    diretorio_atual = os.path.dirname(sys.executable)
else:
    diretorio_atual = os.path.dirname(os.path.abspath(__file__))

PASTA_SNAPSHOTS = os.path.join(diretorio_atual, "snapshots")
DB_PATH = os.path.join(diretorio_atual, "historico_analises.db")

if not os.path.exists(PASTA_SNAPSHOTS):
    os.makedirs(PASTA_SNAPSHOTS)

caminho_env = os.path.join(diretorio_atual, '.env')
load_dotenv(caminho_env)
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

def iniciar_banco_dados():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS historico (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            data_hora TEXT,
            ip TEXT,
            protocolo TEXT,
            diagnostico TEXT
        )
    ''')
    conn.commit()
    conn.close()

iniciar_banco_dados()

# --- INTERFACE GRÁFICA ---
class AssistenteRedesGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Assistente AIOps - V11.2 (Ultimate Edition + Dados Brutos)")
        self.root.geometry("950x980") # Aumentei um pouquinho a largura para caber as 3 abas
        self.root.configure(padx=20, pady=20)

        self.lista_ips_carregada = []
        self.passos_totais = 1
        self.passos_concluidos = 0

        if not GROQ_API_KEY:
            messagebox.showwarning("Aviso", "⚠️ GROQ_API_KEY não encontrada no arquivo .env!")

        # --- CREDENCIAIS ---
        frame_cred = ttk.LabelFrame(root, text="Acesso e Alvos (Huawei)", padding=(10, 10))
        frame_cred.pack(fill="x", pady=(0, 10))

        ttk.Label(frame_cred, text="IP Único:").grid(row=0, column=0, sticky="w", pady=5)
        self.entry_ip = ttk.Entry(frame_cred, width=20)
        self.entry_ip.grid(row=0, column=1, padx=5, pady=5)
        self.entry_ip.insert(0, os.getenv("ROUTER_IP", "10.0.0.1"))

        self.btn_carregar = ttk.Button(frame_cred, text="📄 Carregar Lista TXT", command=self.carregar_ficheiro_ips)
        self.btn_carregar.grid(row=0, column=2, columnspan=2, padx=15, pady=5, sticky="ew")

        ttk.Label(frame_cred, text="Usuário:").grid(row=1, column=0, sticky="w", pady=5)
        self.entry_user = ttk.Entry(frame_cred, width=20)
        self.entry_user.grid(row=1, column=1, padx=5, pady=5)
        self.entry_user.insert(0, os.getenv("ROUTER_USER", "admin"))

        ttk.Label(frame_cred, text="Senha:").grid(row=1, column=2, sticky="w", padx=(15,0), pady=5)
        self.entry_pass = ttk.Entry(frame_cred, width=20, show="*") 
        self.entry_pass.grid(row=1, column=3, padx=5, pady=5)
        self.entry_pass.insert(0, os.getenv("ROUTER_PASS", ""))

        ttk.Label(frame_cred, text="Porta:").grid(row=2, column=0, sticky="w", pady=5)
        self.entry_porta = ttk.Entry(frame_cred, width=10)
        self.entry_porta.grid(row=2, column=1, sticky="w", padx=5, pady=5)
        self.entry_porta.insert(0, os.getenv("ROUTER_PORT", "")) 

        # --- LAYOUT DE MÓDULOS ---
        frame_proto = ttk.LabelFrame(root, text="Módulos de Análise AIOps", padding=(10, 10))
        frame_proto.pack(fill="x", pady=(0, 10))

        self.var_protocolo = tk.StringVar(value="BGP_IPV4_DEEP") 
        
        ttk.Radiobutton(frame_proto, text="🌐 BGP IPv4 (Resumo)", variable=self.var_protocolo, value="BGP_IPV4").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        ttk.Radiobutton(frame_proto, text="🌐 BGP IPv6 (Resumo)", variable=self.var_protocolo, value="BGP_IPV6").grid(row=0, column=1, sticky="w", padx=10, pady=5)
        
        ttk.Radiobutton(frame_proto, text="🕵️ BGP IPv4 (Deep Dive/Filtro)", variable=self.var_protocolo, value="BGP_IPV4_DEEP").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        ttk.Radiobutton(frame_proto, text="🕵️ BGP IPv6 (Deep Dive/Filtro)", variable=self.var_protocolo, value="BGP_IPV6_DEEP").grid(row=1, column=1, sticky="w", padx=10, pady=5)

        ttk.Radiobutton(frame_proto, text="🔗 OSPF (Adjacências)", variable=self.var_protocolo, value="OSPF").grid(row=2, column=0, sticky="w", padx=10, pady=5)
        ttk.Radiobutton(frame_proto, text="🚇 MPLS LDP (Sessões)", variable=self.var_protocolo, value="MPLS_LDP").grid(row=2, column=1, sticky="w", padx=10, pady=5)
        
        ttk.Radiobutton(frame_proto, text="🔌 Interfaces (Erros/Drops)", variable=self.var_protocolo, value="INTERFACES").grid(row=3, column=0, sticky="w", padx=10, pady=5)
        ttk.Radiobutton(frame_proto, text="🚨 Logs Avançados", variable=self.var_protocolo, value="LOGS_AVANCADOS").grid(row=3, column=1, sticky="w", padx=10, pady=5)

        # --- CONTROLE ---
        frame_botoes = ttk.Frame(root)
        frame_botoes.pack(fill="x", pady=(0, 10))

        self.btn_snapshot = ttk.Button(frame_botoes, text="📸 Golden Config", command=lambda: self.iniciar_processo("snapshot"))
        self.btn_snapshot.pack(side="left", fill="x", expand=True, padx=(0, 5), ipady=5)

        self.btn_iniciar = ttk.Button(frame_botoes, text="⚡ Executar Análise Groq", command=lambda: self.iniciar_processo("analise"))
        self.btn_iniciar.pack(side="left", fill="x", expand=True, padx=(5, 5), ipady=5)

        self.btn_salvar = ttk.Button(frame_botoes, text="💾 Exportar TXT", command=self.salvar_relatorio, state="disabled")
        self.btn_salvar.pack(side="left", fill="x", expand=True, padx=(5, 5), ipady=5)

        style = ttk.Style()
        style.configure("Sair.TButton", foreground="red", font=("Arial", 9, "bold"))
        self.btn_sair = ttk.Button(frame_botoes, text="🚪 Sair", style="Sair.TButton", command=self.sair_app)
        self.btn_sair.pack(side="right", fill="x", expand=True, padx=(5, 0), ipady=5)

        self.lbl_status = ttk.Label(root, text="Pronto para iniciar.", font=("Arial", 10, "italic"))
        self.lbl_status.pack(pady=(0, 5))

        self.progress_bar = ttk.Progressbar(root, orient="horizontal", mode="determinate", length=100)
        self.progress_bar.pack(fill="x", pady=(0, 10))

        # --- SISTEMA DE ABAS (AGORA COM 3 ABAS) ---
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, pady=(5, 0))

        # Aba 1: Inteligência Artificial
        self.tab_diagnostico = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_diagnostico, text="🧠 Diagnóstico IA")
        self.txt_resultado = scrolledtext.ScrolledText(self.tab_diagnostico, wrap=tk.WORD, font=("Consolas", 10))
        self.txt_resultado.pack(fill="both", expand=True, padx=5, pady=5)

        # Aba 2: Logs do Sistema (O que o Python está fazendo)
        self.tab_logs = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_logs, text="⚙️ Logs do Sistema")
        self.txt_logs = scrolledtext.ScrolledText(self.tab_logs, wrap=tk.WORD, font=("Consolas", 9), fg="darkgreen")
        self.txt_logs.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Aba 3: DADOS BRUTOS (A novidade!)
        self.tab_bruto = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_bruto, text="📄 Dados Brutos (CLI)")
        self.txt_bruto = scrolledtext.ScrolledText(self.tab_bruto, wrap=tk.WORD, font=("Consolas", 9), fg="darkblue")
        self.txt_bruto.pack(fill="both", expand=True, padx=5, pady=5)

        self.log_sistema("Sistema V11.2 (Com Aba de Dados Brutos) iniciado.")

    # --- FUNÇÕES DE APOIO ---
    def atualizar_interface_segura(self, texto):
        self.root.after(0, lambda: self.txt_resultado.insert(tk.END, texto))
        self.root.after(0, lambda: self.txt_resultado.see(tk.END))

    def log_sistema(self, mensagem):
        timestamp = datetime.now().strftime("%H:%M:%S")
        texto = f"[{timestamp}] {mensagem}\n"
        self.root.after(0, lambda: self.txt_logs.insert(tk.END, texto))
        self.root.after(0, lambda: self.txt_logs.see(tk.END))

    def atualizar_dados_brutos(self, texto):
        # Função exclusiva para injetar texto na nova aba
        self.root.after(0, lambda: self.txt_bruto.insert(tk.END, texto + "\n\n"))
        self.root.after(0, lambda: self.txt_bruto.see(tk.END))

    def incrementar_progresso(self):
        self.passos_concluidos += 1
        pct = (self.passos_concluidos / self.passos_totais) * 100
        self.root.after(0, lambda: self.progress_bar.configure(value=pct))

    def carregar_ficheiro_ips(self):
        caminho = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if caminho:
            with open(caminho, "r") as f:
                ips = [linha.strip() for linha in f.readlines() if linha.strip()]
            if ips:
                self.lista_ips_carregada = ips
                self.entry_ip.delete(0, tk.END)
                self.entry_ip.insert(0, f"[{len(ips)} IPs em Lote]")
                self.entry_ip.config(state="disabled")

    def sair_app(self):
        if messagebox.askyesno("Encerrar", "Deseja fechar o sistema?"):
            self.root.destroy()
            os._exit(0) 

    def salvar_no_banco(self, ip, protocolo, diagnostico):
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            data_hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute('INSERT INTO historico (data_hora, ip, protocolo, diagnostico) VALUES (?, ?, ?, ?)', 
                           (data_hora, ip, protocolo, diagnostico))
            conn.commit()
            conn.close()
        except Exception as e:
            pass

    # --- MOTOR PRINCIPAL ---
    def iniciar_processo(self, modo):
        if not GROQ_API_KEY and modo == "analise":
            messagebox.showerror("Erro", "GROQ_API_KEY não configurada no arquivo .env!")
            return

        self.btn_iniciar.config(state="disabled")
        self.btn_snapshot.config(state="disabled")
        
        # Limpa as abas de resultado e brutos a cada nova execução
        self.txt_resultado.delete(1.0, tk.END)
        self.txt_bruto.delete(1.0, tk.END) 
        
        self.progress_bar["value"] = 0
        self.lbl_status.config(text="A conectar e processar na nuvem Groq...")
        self.notebook.select(self.tab_diagnostico)

        ips = self.lista_ips_carregada if self.lista_ips_carregada else [self.entry_ip.get().strip()]
        self.passos_totais = len(ips) * 3
        self.passos_concluidos = 0

        threading.Thread(target=self.motor_multithreading, args=(ips, modo)).start()

    def motor_multithreading(self, ips, modo):
        porta = self.entry_porta.get()
        user = self.entry_user.get()
        senha = self.entry_pass.get()
        protocolo = self.var_protocolo.get() 

        # Cinto de Segurança: 1 roteador por vez para não estourar tokens do Groq
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            futuros = [executor.submit(self.processar_roteador, ip, porta, user, senha, protocolo, modo) for ip in ips]
            concurrent.futures.wait(futuros)

        self.root.after(0, lambda: self.lbl_status.config(text="Processo Concluído!"))
        self.root.after(0, lambda: self.btn_iniciar.config(state="normal"))
        self.root.after(0, lambda: self.btn_snapshot.config(state="normal"))
        if modo == "analise":
            self.root.after(0, lambda: self.btn_salvar.config(state="normal"))

    def processar_roteador(self, ip, porta, user, senha, protocolo, modo):
        try:
            self.log_sistema(f"[{ip}] Tentando conexão SSH...")
            equipamento = {
                'device_type': 'huawei', 'host': ip, 'port': int(porta),
                'username': user, 'password': senha, 'conn_timeout': 15
            }
            conexao = ConnectHandler(**equipamento)
            self.incrementar_progresso()
            
            self.log_sistema(f"[{ip}] Coletando dados do módulo: {protocolo}...")
            dados_brutos = ""
            
            # --- EXTRAÇÃO DE DADOS ---
            if protocolo in ["BGP_IPV4_DEEP", "BGP_IPV6_DEEP"]:
                cmd_base = "display bgp peer" if protocolo == "BGP_IPV4_DEEP" else "display bgp ipv6 peer"
                self.log_sistema(f"[{ip}] Coletando a tabela inicial ({cmd_base})...")
                resumo = conexao.send_command(cmd_base)
                
                peers_encontrados = []
                estados_falha = ["Idle", "Active", "Connect", "OpenSent", "OpenConfirm"]
                
                for linha in resumo.split('\n'):
                    if any(estado in linha for estado in estados_falha):
                        partes = linha.split()
                        if partes:
                            peers_encontrados.append(partes[0])
                
                peers_encontrados = list(set(peers_encontrados))
                
                if not peers_encontrados:
                    dados_brutos = f"--- TABELA DE PEERS ---\n{resumo}\n\n[INFO DO PYTHON] Todos os vizinhos BGP estão 'Established'. Não foi necessário executar o verbose."
                    self.log_sistema(f"[{ip}] Todos os peers Established. Saltando verbose.")
                else:
                    self.log_sistema(f"[{ip}] {len(peers_encontrados)} peers com falha encontrados. Extraindo verbose...")
                    dados_brutos = f"--- TABELA DE PEERS ---\n{resumo}\n\n--- DETALHES VERBOSE (APENAS FALHAS) ---\n"
                    
                    # Cinto de segurança: Max 10 peers para o Groq
                    for peer_ip in peers_encontrados[:10]:
                        self.log_sistema(f"[{ip}] Executando verbose no IP crítico: {peer_ip}")
                        if protocolo == "BGP_IPV4_DEEP":
                            out_verb = conexao.send_command(f"display bgp peer {peer_ip} verbose")
                        else:
                            out_verb = conexao.send_command(f"display bgp ipv6 peer {peer_ip} verbose")
                        dados_brutos += f"\n[PEER COM FALHA: {peer_ip}]\n{out_verb}\n"

            elif protocolo == "BGP_IPV4": 
                dados_brutos = conexao.send_command("display bgp peer")
            elif protocolo == "BGP_IPV6": 
                dados_brutos = conexao.send_command("display bgp ipv6 peer")
            elif protocolo == "OSPF": 
                dados_brutos = conexao.send_command("display ospf peer")
            elif protocolo == "MPLS_LDP": 
                dados_brutos = conexao.send_command("display mpls ldp session")
            elif protocolo == "INTERFACES": 
                ints = conexao.send_command("display interface brief")
                errs = conexao.send_command("display interface counters errors")
                dados_brutos = f"--- STATUS FÍSICO ---\n{ints}\n\n--- ERROS E DROPS ---\n{errs}"
            elif protocolo == "LOGS_AVANCADOS":
                logs = conexao.send_command("display logbuffer size 100")
                traps = conexao.send_command("display trapbuffer size 30")
                dados_brutos = f"--- ÚLTIMOS LOGS ---\n{logs}\n\n--- ÚLTIMOS TRAPS ---\n{traps}"

            conexao.disconnect()
            self.incrementar_progresso()

            # -> AQUI INJETAMOS OS DADOS NA NOVA ABA! <-
            titulo_bruto = f"========= {protocolo} | IP: {ip} =========\n"
            self.atualizar_dados_brutos(titulo_bruto + dados_brutos + "\n" + "="*50)

            caminho_snapshot = os.path.join(PASTA_SNAPSHOTS, f"{ip}_{protocolo}.txt")
            if modo == "snapshot":
                with open(caminho_snapshot, "w") as f: f.write(dados_brutos)
                self.atualizar_interface_segura(f"✅ [{ip}] Golden Config salva!\n\n")
                self.incrementar_progresso()
                return

            self.log_sistema(f"[{ip}] Enviando para a IA (Groq)...")
            
            # Limite super restrito para o plano gratuito (Max 10k caracteres)
            texto_seguro = dados_brutos[-10000:] if len(dados_brutos) > 10000 else dados_brutos

            # Trava para saída vazia (Ex: Sem BGP IPv6 configurado)
            if not texto_seguro.strip():
                texto_seguro = "[AVISO DO SISTEMA PYTHON: O roteador não retornou nenhum dado. O protocolo selecionado está vazio ou não configurado neste equipamento.]"

            # INSTRUÇÕES DE PROMPT
            if "DEEP" in protocolo:
                instrucao = """Você é um Arquiteto de Redes Sênior avaliando a saída 'verbose' de peers BGP da Huawei. Responda em PORTUGUÊS.
                Não descreva o que está normal. Vá direto ao ponto: diga quais peers estão com erro e aponte a causa técnica (ex: Erro de Hold Timer, Capabilities não suportadas, Last Error, Limits). Se o Python informar que todos estão 'Established', apenas avise que a rede está saudável."""
                prompt = f"Avalie o deep dive do BGP:\n{texto_seguro}"
            elif protocolo == "LOGS_AVANCADOS":
                instrucao = """Você é um Arquiteto de Redes Sênior avaliando Huawei. Responda em PORTUGUÊS. Formate assim:
                🔴 **ERRO IDENTIFICADO:** [Resumo]
                🧠 **CAUSA RAIZ:** [Explicação]
                🛠️ **PLANO DE AÇÃO:** [Comandos de correção]"""
                prompt = f"Avalie estes logs:\n{texto_seguro}"
            elif protocolo == "INTERFACES":
                instrucao = """Você é um Engenheiro de Redes avaliando a saúde física de portas Huawei. Responda em PORTUGUÊS.
                Ignore portas em administratively down. Foque apenas em portas fisicamente DOWN, ou portas UP mas com muitos erros (InErrors, OutErrors, Drops, CRC). Formate a resposta de forma direta."""
                prompt = f"Avalie as interfaces:\n{texto_seguro}"
            elif os.path.exists(caminho_snapshot):
                with open(caminho_snapshot, "r") as f: estado_ideal = f.read()
                ideal_seguro = estado_ideal[-10000:] if len(estado_ideal) > 10000 else estado_ideal
                instrucao = "Responda em PORTUGUÊS. Compare o estado IDEAL com o ATUAL e diga APENAS o que piorou, caiu ou sumiu na rede."
                prompt = f"IDEAL:\n{ideal_seguro}\n\nATUAL:\n{texto_seguro[-10000:]}"
            else:
                instrucao = f"Você é um Engenheiro de Redes. Responda em PORTUGUÊS. Analise os dados de {protocolo} da Huawei. Identifique apenas sessões/peers que não estão conectadas/established/operational."
                prompt = f"Saída atual:\n{texto_seguro}"

            # CHAMADA API GROQ
            cliente_groq = Groq(api_key=GROQ_API_KEY)
            resposta = cliente_groq.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=[
                    {"role": "system", "content": instrucao},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1 
            )

            diagnostico_final = resposta.choices[0].message.content
            self.atualizar_interface_segura(f"=== DIAGNÓSTICO {ip} ({protocolo}) ===\n{diagnostico_final}\n{'-'*60}\n\n")
            self.salvar_no_banco(ip, protocolo, diagnostico_final)
            self.incrementar_progresso()

        except Exception as e:
            erro_msg = f"❌ [{ip}] FALHA: {str(e)}"
            self.atualizar_interface_segura(f"{erro_msg}\n{'-'*60}\n\n")
            self.log_sistema(f"[{ip}] ERRO CRÍTICO: {str(e)}")
            self.salvar_no_banco(ip, protocolo, erro_msg)
            self.incrementar_progresso()
            self.incrementar_progresso()

    def salvar_relatorio(self):
        caminho = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="Relatorio_AIOps.txt")
        if caminho:
            try:
                with open(caminho, "w", encoding="utf-8") as f:
                    f.write(self.txt_resultado.get(1.0, tk.END))
                messagebox.showinfo("Sucesso", "Relatório exportado!")
            except Exception as e:
                pass

if __name__ == "__main__":
    janela_principal = tk.Tk()
    app = AssistenteRedesGUI(janela_principal)
    janela_principal.mainloop()