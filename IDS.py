import sys
import time
import scapy.all as scapy
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QVBoxLayout, QTextEdit, QFileDialog,
    QLineEdit, QHBoxLayout
)
from PyQt5.QtCore import QThread, pyqtSignal, QTimer, Qt
from PyQt5.QtGui import QFont
from collections import defaultdict
import subprocess
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas


class IDSWorker(QThread):
    packet_detected = pyqtSignal(str)
    attack_detected = pyqtSignal(str)
    update_graph = pyqtSignal(int)

    def __init__(self):
        super().__init__()
        self.running = True
        self.packet_count = defaultdict(int)
        self.packet_per_second = 0
        self.attack_threshold = 100

    def run(self):
        try:
            scapy.sniff(
                filter="ip",
                prn=self.process_packet,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except PermissionError:
            self.attack_detected.emit("Erro de permissão. Execute como administrador.")

    def process_packet(self, packet):
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            self.packet_count[src_ip] += 1
            self.packet_per_second += 1

            # Detectar ataques baseados em threshold
            if self.packet_count[src_ip] > self.attack_threshold:
                self.attack_detected.emit(f"ALERTA: Possível ataque de {src_ip}")

            self.packet_detected.emit(f"Pacote de {src_ip} para {dst_ip}")

    def stop(self):
        self.running = False

    def scan_network(self, target_ip):
        try:
            result = subprocess.run(
                ['nmap', '-p', '22-443', target_ip],
                capture_output=True,
                text=True
            )
            scan_result = result.stdout
            self.attack_detected.emit(f"Escaneamento concluído para {target_ip}. Resultados:\n{scan_result}")
        except Exception as e:
            self.attack_detected.emit(f"Erro ao realizar o escaneamento: {e}")


class IDSApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IDS - Sistema de Detecção de Intrusões")
        self.setGeometry(100, 100, 1000, 800)
        self.setStyleSheet("background-color: #2C3E50; color: white;")
        self.setFont(QFont("Orbitron", 12))

        # Layout principal
        layout = QVBoxLayout()

        # Texto de monitoramento
        self.label = QLabel("Monitoramento de rede em tempo real...")
        self.label.setFont(QFont("Orbitron", 14))
        layout.addWidget(self.label)

        # Caixa de texto para exibir pacotes e alertas
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        layout.addWidget(self.text_area)

        # Campo de filtro
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Digite um filtro para pesquisar...")
        self.filter_input.setStyleSheet("background-color: #34495E; color: white; padding: 5px;")
        self.filter_input.textChanged.connect(self.apply_filter)
        layout.addWidget(self.filter_input)

        # Mensagem de alerta sutil
        self.alert_message = QLabel("")
        self.alert_message.setStyleSheet("color: red; font-size: 16px;")
        self.alert_message.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.alert_message)

        # Botões
        button_layout = QHBoxLayout()
        self.start_button = self.create_button("Iniciar Monitoramento", "#1ABC9C", self.start_monitoring)
        self.stop_button = self.create_button("Parar Monitoramento", "#E74C3C", self.stop_monitoring)
        self.save_button = self.create_button("Salvar Relatório", "#F39C12", self.save_report)
        self.scan_button = self.create_button("Escanear Rede", "#3498DB", self.scan_network)

        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.scan_button)
        layout.addLayout(button_layout)

        # Gráfico de tráfego em tempo real
        self.fig, self.ax = plt.subplots(figsize=(5, 4))
        self.ax.set_facecolor("#34495E")  # Define o fundo do gráfico
        self.fig.patch.set_facecolor("#2C3E50")  # Fundo da área total do gráfico
        self.canvas = FigureCanvas(self.fig)
        layout.addWidget(self.canvas)

        # Rodapé
        self.footer_label = QLabel("Desenvolvido por Gabriel Barbosa")
        self.footer_label.setStyleSheet("color: #F1C40F; text-align: center;")
        self.footer_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.footer_label)

        self.setLayout(layout)

        # Threads e dados
        self.ids_worker = IDSWorker()
        self.ids_worker.packet_detected.connect(self.display_packet)
        self.ids_worker.attack_detected.connect(self.display_attack)
        self.traffic_data = []
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_graph)
        self.all_logs = []

    def create_button(self, text, color, callback):
        button = QPushButton(text)
        button.setStyleSheet(f"background-color: {color}; color: white; border-radius: 5px; padding: 10px;")
        button.clicked.connect(callback)
        return button

    def start_monitoring(self):
        self.text_area.append("Monitoramento iniciado.")
        self.ids_worker.start()
        self.timer.start(1000)

    def stop_monitoring(self):
        self.ids_worker.stop()
        self.timer.stop()
        self.alert_message.setText("")  # Limpar a mensagem de alerta
        self.text_area.append("Monitoramento parado.")

    def display_packet(self, packet_info):
        self.all_logs.append(packet_info)
        self.text_area.append(packet_info)

    def display_attack(self, attack_info):
        self.all_logs.append(attack_info)
        self.text_area.append(attack_info)
        self.show_alert(attack_info)

    def show_alert(self, message):
        # Exibir alerta visual sutil
        self.alert_message.setText(f"Possível ataque detectado: {message}")
        # Remover a mensagem após 5 segundos
        QTimer.singleShot(5000, lambda: self.alert_message.setText(""))

    def save_report(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self, "Salvar Relatório", "", "Relatórios (*.txt)", options=options)
        if file_path:
            with open(file_path, "w") as file:
                file.write("\n".join(self.all_logs))
            self.text_area.append(f"Relatório salvo em {file_path}")

    def scan_network(self):
        target_ip, _ = QFileDialog.getOpenFileName(self, "Escolher alvo para escaneamento")
        if target_ip:
            self.ids_worker.scan_network(target_ip)

    def apply_filter(self):
        filter_text = self.filter_input.text().lower()
        filtered_logs = [log for log in self.all_logs if filter_text in log.lower()]
        self.text_area.clear()
        self.text_area.append("\n".join(filtered_logs))

    def update_graph(self):
        self.traffic_data.append(self.ids_worker.packet_per_second)
        self.ids_worker.packet_per_second = 0
        self.ax.clear()
        self.ax.set_facecolor("#34495E")  # Fundo do gráfico atualizado
        self.ax.plot(self.traffic_data, color="cyan", label="Pacotes por segundo")
        self.ax.legend(loc="upper right", facecolor="#2C3E50", edgecolor="white", labelcolor="white")
        self.canvas.draw()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = IDSApp()
    window.show()
    sys.exit(app.exec_())
