import sys
import os
import hashlib
import logging
import requests
import ssl
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
from lxml import etree
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QPushButton, QFileDialog, QWidget, QHBoxLayout, QLabel, QHeaderView, QLineEdit, QComboBox
)
from PyQt5.QtCore import Qt
from docx import Document
import pandas as pd
import tempfile
import random
from datetime import datetime

# 配置日志记录
logging.basicConfig(
    filename="link_scanner.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filemode="w"  # 每次运行时覆盖日志文件
)

class SSLAdapter(HTTPAdapter):
    """
    自定义适配器用于在请求中配置SSL设置。
    """
    def __init__(self, ssl_context=None, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = self.ssl_context
        return super().init_poolmanager(*args, **kwargs)

class LinkScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("文档链接扫描工具")  # 设置窗口标题
        self.setGeometry(300, 300, 1000, 700)  # 设置窗口大小和位置

        self.scanned_data = []  # 存储扫描到的数据
        self.temp_dir = tempfile.mkdtemp(prefix="link_scanner_")  # 创建临时目录用于下载
        self.supported_domains = {"*"}  # 默认支持所有域名

        # 创建数据表
        self.table = QTableWidget()
        self.table.setColumnCount(5)  # 设置列数
        self.table.setHorizontalHeaderLabels(["文档路径", "链接 URL", "标题 Label", "文件哈希 (MD5)", "对应的文档"])  # 设置表头

        # 调整列宽以填充表格
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)  # 设置列宽填充模式

        # 域名输入控件
        self.domain_label = QLabel("支持的网站域名 (用逗号分隔，* 表示所有):")
        self.domain_input = QLineEdit()
        self.domain_input.setText("*")  # 默认输入值为 "*"
        self.domain_input.setPlaceholderText("例如: example.com, sz.gov.cn, *")
        self.domain_input.textChanged.connect(self.update_supported_domains)  # 输入变化时更新支持的域名

        # 创建按钮
        self.scan_button = QPushButton("选择文件并扫描")  # 扫描按钮
        self.scan_button.clicked.connect(self.scan_links)  # 点击扫描按钮时执行扫描

        self.export_button = QPushButton("导出为 Excel")  # 导出按钮
        self.export_button.clicked.connect(self.export_to_excel)  # 点击导出按钮执行导出

        self.status_label = QLabel("状态: 等待操作")  # 状态标签
        self.status_label.setAlignment(Qt.AlignLeft)  # 设置左对齐

        # 布局设计
        domain_layout = QHBoxLayout()
        domain_layout.addWidget(self.domain_label)  # 添加域名标签
        domain_layout.addWidget(self.domain_input)  # 添加域名输入框

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.scan_button)  # 添加扫描按钮
        button_layout.addWidget(self.export_button)  # 添加导出按钮

        layout = QVBoxLayout()
        layout.addLayout(domain_layout)  # 添加域名输入布局
        layout.addWidget(self.table)  # 添加表格
        layout.addLayout(button_layout)  # 添加按钮布局
        layout.addWidget(self.status_label)  # 添加状态标签

        container = QWidget()
        container.setLayout(layout)  # 设置主容器的布局
        self.setCentralWidget(container)  # 设置中心窗口为容器

        logging.info("Application initialized successfully.")  # 日志记录应用初始化成功
        logging.info(f"Temporary download directory created at {self.temp_dir}")  # 日志记录临时目录创建成功

    def update_supported_domains(self):
        input_text = self.domain_input.text()  # 获取用户输入的域名
        if not input_text.strip():  # 如果输入为空，默认设置为"*"
            self.supported_domains = {"*"}
        else:
            self.supported_domains = set(domain.strip() for domain in input_text.split(",") if domain.strip())
        logging.info(f"Updated supported domains: {self.supported_domains}")  # 日志记录更新的支持域名

    def compute_md5(self, file_path):
        try:
            logging.info(f"Computing MD5 hash for file: {file_path}")  # 日志记录正在计算的文件
            with open(file_path, 'rb') as f:
                file_hash = hashlib.md5()
                while chunk := f.read(8192):  # 分块读取文件
                    file_hash.update(chunk)  # 更新哈希值
            md5_hash = file_hash.hexdigest()  # 获取十六进制的哈希值
            logging.info(f"MD5 hash for {file_path}: {md5_hash}")  # 日志记录MD5哈希值
            return md5_hash
        except Exception as e:
            logging.error(f"Error calculating MD5 for {file_path}: {e}")  # 日志记录错误
            return "Error"

    def create_ssl_session(self):
        try:
            context = ssl.create_default_context()  # 创建默认的SSL上下文
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # 禁用旧的SSL版本
            session = requests.Session()  # 创建请求会话
            adapter = SSLAdapter(ssl_context=context)  # 使用自定义的SSL适配器
            session.mount("https://", adapter)  # 将适配器挂载到HTTPS请求
            return session
        except Exception as e:
            logging.error(f"Error creating SSL session: {e}")  # 日志记录错误
            return requests.Session()  # 回退到默认会话

    def download_file(self, url, retries=3):
        attempt = 0
        session = self.create_ssl_session()  # 使用自定义SSL会话
        while attempt < retries:
            try:
                logging.info(f"Downloading file from URL: {url} (Attempt {attempt + 1})")  # 日志记录下载尝试
                local_filename = os.path.join(self.temp_dir, os.path.basename(url.split('?')[0]))  # 确定本地文件名
                response = session.get(url, stream=True, timeout=10)  # 发起GET请求
                response.raise_for_status()  # 检查请求是否成功

                with open(local_filename, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):  # 分块写入文件
                        f.write(chunk)

                logging.info(f"File downloaded: {local_filename}")  # 日志记录下载成功
                file_hash = self.compute_md5(local_filename)  # 计算下载文件的MD5哈希值
                return local_filename, file_hash  # 返回文件路径和哈希值
            except requests.RequestException as e:
                logging.warning(f"Error downloading file from {url}: {e}. Retrying...")  # 日志记录下载错误并重试
                attempt += 1

        logging.error(f"Failed to download file from {url} after {retries} attempts.")  # 日志记录失败信息
        return None, "Error"  # 返回错误

    def extract_hyperlinks(self, docx_path):
        links_with_labels = []  # 用于存储提取的链接和标签
        try:
            logging.info(f"Parsing document: {docx_path}")  # 日志记录正在解析的文档
            document = Document(docx_path)  # 加载文档

            for paragraph in document.paragraphs:
                paragraph_xml = paragraph._element.xml
                root = etree.fromstring(paragraph_xml)  # 解析段落XML

                field_start = False
                hyperlink_url = None
                hyperlink_label = None

                for elem in root.iter():
                    if elem.tag.endswith("fldChar") and elem.get("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}fldCharType") == "begin":
                        field_start = True
                        hyperlink_url = None
                        hyperlink_label = None

                    if field_start and elem.tag.endswith("instrText") and "HYPERLINK" in elem.text:
                        hyperlink_url = elem.text.split('"')[1]  # 提取引号中的URL

                    if field_start and elem.tag.endswith("t"):
                        hyperlink_label = elem.text.strip()

                    if elem.tag.endswith("fldChar") and elem.get("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}fldCharType") == "end":
                        field_start = False
                        if hyperlink_url and hyperlink_label:
                            domain = urlparse(hyperlink_url).netloc
                            if "*" in self.supported_domains or domain in self.supported_domains:
                                links_with_labels.append({
                                    "链接 URL": hyperlink_url,
                                    "标题 Label": hyperlink_label
                                })
                                logging.debug(f"Extracted: URL={hyperlink_url}, Label={hyperlink_label}")  # 日志记录提取的链接和标签

        except Exception as e:
            logging.error(f"Error parsing document {docx_path}: {e}")  # 日志记录解析错误

        return links_with_labels  # 返回提取的链接和标签

    def scan_links(self):
        files, _ = QFileDialog.getOpenFileNames(self, "选择文档", "", "Word 文档 (*.docx)")  # 打开文件对话框选择文档
        if not files:  # 如果没有选择文件
            self.status_label.setText("状态: 未选择任何文件")  # 更新状态信息
            logging.warning("No files selected for scanning.")  # 日志记录未选择文件
            return

        self.scanned_data.clear()  # 清除之前的扫描数据
        self.table.setRowCount(0)  # 清除表格
        logging.info(f"Starting scan for {len(files)} file(s).")  # 日志记录开始扫描的文件数量

        for file_path in files:
            try:
                links = self.extract_hyperlinks(file_path)  # 提取链接和标签

                # 处理每个链接
                for link in links:
                    downloaded_file, file_hash = self.download_file(link["链接 URL"])  # 下载链接文件
                    self.scanned_data.append({
                        "文档路径": os.path.abspath(file_path),  # 文档的绝对路径
                        "链接 URL": link["链接 URL"],  # 链接URL
                        "标题 Label": link["标题 Label"],  # 链接标题
                        "文件哈希 (MD5)": file_hash  # 文件的MD5哈希值
                    })

                    # 获取对应的文件信息，构造下拉选项
                    corresponding_files = self.get_file_info_by_hash(file_hash)  
                    combo_box = QComboBox()  # 创建下拉列表
                    for file_info in corresponding_files:
                        option = f"{file_info['文件名']} - 最后更新时间: {file_info['更新时间']}"
                        combo_box.addItem(option, file_info['文件ID'])  # 添加选项，文件ID为实际值

                    # 更新表格
                    row = self.table.rowCount()  # 获取当前行数
                    self.table.insertRow(row)  # 在表格中插入新行
                    self.table.setItem(row, 0, QTableWidgetItem(os.path.abspath(file_path)))  # 设置文档路径
                    self.table.setItem(row, 1, QTableWidgetItem(link["链接 URL"] or "无链接"))  # 设置链接URL
                    self.table.setItem(row, 2, QTableWidgetItem(link["标题 Label"] or "无标题"))  # 设置链接标题
                    self.table.setItem(row, 3, QTableWidgetItem(file_hash or "Error"))  # 设置文件哈希
                    self.table.setCellWidget(row, 4, combo_box)  # 在新列设置下拉列表

                self.status_label.setText(f"状态: 成功扫描 {len(self.scanned_data)} 条链接")  # 更新状态信息
                logging.info(f"File {file_path} scanned successfully: {len(links)} links extracted.")  # 日志记录扫描成功
            except Exception as e:
                self.status_label.setText(f"状态: 扫描文件 {file_path} 时发生错误: {e}")  # 更新状态信息
                logging.error(f"Error scanning {file_path}: {e}")  # 日志记录扫描错误

    def get_file_info_by_hash(self, hash_value):
        """
        根据提供的哈希值随机返回包含文件信息的对象数组。

        参数:
        hash_value (str): 输入的文件哈希值。

        返回:
        list: 包含文件信息的对象数组。
        """
        if not hash_value:
            raise ValueError("输入的哈希值不能为空！")  # 抛出异常

        # 随机生成文件信息的数量（0-5个）
        num_files = random.randint(0, 5)
        file_info_list = []

        for _ in range(num_files):
            file_info = {
                "文件名": f"文件_{random.randint(1, 100)}.txt",  # 随机文件名
                "文件ID": random.randint(1000, 9999),          # 随机文件ID
                "更新时间": datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # 当前时间作为更新时间
            }
            file_info_list.append(file_info)

        return file_info_list

    def export_to_excel(self):
        """
        导出扫描结果到Excel文件中。
        """
        if not self.scanned_data:  # 如果没有扫描结果
            self.status_label.setText("状态: 无扫描结果可导出")  # 更新状态信息
            logging.warning("No scan results to export.")  # 日志记录无扫描结果
            return

        save_path, _ = QFileDialog.getSaveFileName(self, "保存为 Excel 文件", "", "Excel 文件 (*.xlsx)")  # 打开保存对话框
        if not save_path:  # 如果没有选择保存路径
            self.status_label.setText("状态: 未选择保存路径")  # 更新状态信息
            logging.warning("No save path selected for exporting results.")  # 日志记录未选择保存路径
            return

        try:
            # 准备导出的数据，包含“对应的文档”列
            export_data = []
            for i, data in enumerate(self.scanned_data):
                # 访问下拉列表中的当前选中项
                combo_box = self.table.cellWidget(i, 4)
                selected_file_id = combo_box.currentData() if combo_box else None
                
                # 将所需数据添加到导出字典中
                export_row = {
                    "文档路径": data["文档路径"],
                    "链接 URL": data["链接 URL"],
                    "标题 Label": data["标题 Label"],
                    "文件哈希 (MD5)": data["文件哈希 (MD5)"],
                    "对应的文档": selected_file_id  # 添加“对应的文档”字段
                }
                export_data.append(export_row)

            # 将数据转换为DataFrame
            df = pd.DataFrame(export_data)  
            df.to_excel(save_path, index=False)  # 导出到Excel文件
            self.status_label.setText(f"状态: 成功导出到 {save_path}")  # 更新状态信息
            logging.info(f"Exported scan results to {save_path}.")  # 日志记录成功导出
        except Exception as e:
            self.status_label.setText(f"状态: 导出 Excel 文件时发生错误: {e}")  # 更新状态信息
            logging.error(f"Error exporting to Excel: {e}")  # 日志记录导出错误

if __name__ == "__main__":
    logging.info("Application started.")  # 日志记录应用启动
    app = QApplication(sys.argv)  # 创建应用程序实例
    window = LinkScannerApp()  # 创建应用程序窗口
    window.show()  # 显示窗口
    sys.exit(app.exec_())  # 进入主事件循环
