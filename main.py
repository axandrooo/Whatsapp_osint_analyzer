# main.py — интерфейс. Обработка данных и формирование отчёта находятся в analyzer.py.
import math
import sys
import queue
import threading
import tkinter as tk
from pathlib import Path
from PIL import Image
from tkinter import filedialog, messagebox, ttk
import customtkinter as ctk
from tkinterdnd2 import DND_FILES, TkinterDnD
from analyzer import (WhatsAppAnalyzer, DocumentSearch, LocalTranscriber, EventData, OfflineTiles, write_table_csv, PhoneLookup)
from patterns import APP_NAME, RULES_VERSION, THREAT_PATTERNS

ctk.set_appearance_mode('dark')
# Общая палитра интерфейса. Свечение рисуется цветными слоями, без alpha.
BG, WHITE, INK, MUTED = '#060F1E', '#0C1C30', '#EAF4FF', '#94ACC5'
NAVY, BORDER, PALE = '#43D7FF', '#204665', '#10253D'
ACCENT, HOVER, SIDEBAR = '#1269C7', '#1683E7', '#071426'
LEVEL_COLORS = {'Низкий': '#41D9A3', 'Средний': '#F4CD68',
                'Высокий': '#FFA064', 'Критический': '#FF6887'}


class SectionStack(ctk.CTkFrame):
    """Страницы с прежним API add/set, управляемые боковой навигацией."""
    def __init__(self, parent, on_select):
        super().__init__(parent, fg_color=WHITE, border_width=1,
                         border_color=BORDER, corner_radius=14)
        self.pages = {}
        self.on_select = on_select
        self.current = None
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

    def add(self, name):
        page = ctk.CTkFrame(self, fg_color=WHITE, corner_radius=12)
        self.pages[name] = page
        if self.current is None:
            self.set(name)
        return page

    def set(self, name):
        if self.current is not None:
            self.pages[self.current].grid_forget()
        self.pages[name].grid(row=0, column=0, sticky='nsew', padx=3, pady=3)
        self.current = name
        self.on_select(name)


def resource_path(name):
    # В EXE ресурсы распаковываются PyInstaller в _MEIPASS.
    base = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent))
    return base / name


def set_windows_app_identity():
    if sys.platform == 'win32':
        import ctypes
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                'WhatsappOsintAnalyzer.Desktop')
        except (AttributeError, OSError) as error:
            print(f'Windows AppUserModelID: {error}', file=sys.stderr)


def apply_window_icon(window):
    if sys.platform != 'win32':
        return
    icon_path = resource_path('icon.ico')

    def apply():
        try:
            if window.winfo_exists():
                # Вызов через метод CTk также запоминает пользовательскую иконку.
                window.iconbitmap(str(icon_path))
        except tk.TclError as error:
            print(f'Не удалось установить иконку: {error}', file=sys.stderr)

    apply()
    # CTk отложенно оформляет заголовок окна; повторяем назначение после него.
    window.after(350, apply)



class ModernOSINTApp(ctk.CTk, TkinterDnD.DnDWrapper):
    def __init__(self):
        set_windows_app_identity()
        super().__init__()
        apply_window_icon(self)
        # CTk управляет DPI и непрозрачностью; DnDWrapper добавляет drag-and-drop.
        self.TkdndVersion = TkinterDnD._require(self)
        self._opacity_restore_job = None
        self.title(APP_NAME)
        self.geometry('1360x860')
        self.minsize(1100, 720)
        self.configure(fg_color=BG)
        self.analyzer = WhatsAppAnalyzer()
        self.all_results = []
        self.finding_items = []
        self.filtered_items = []
        self.rejected_files = []
        self.page = 0
        self.page_size = 200
        self.pending_search = None
        self.busy = False
        self.events = queue.Queue()
        self._style_table()
        self._build_shell()
        self._build_header()
        self._build_metrics()
        self.status = self.label(self.workspace, 'Загрузите текстовые экспорты WhatsApp или откройте демонстрацию.', color=MUTED)
        self.status.pack(side='bottom', anchor='w', padx=24, pady=(0, 10))
        self.tabview = SectionStack(self.workspace, self._mark_section)
        self.tabview.pack(fill='both', expand=True, padx=20, pady=(0, 10))
        self.tabs = {name: self.tabview.add(name) for name in
                     ('Совпадения', 'Статистика', 'По файлам', 'Сеть контактов', 'Импорт', 'Документы', 'Аудио', 'Карта событий', 'Поиск по номеру', 'Информация')}
        self._build_findings()
        self._build_network()
        self._build_info()
        self.refresh_results()
        self._build_extra_tools()
        self.bind('<FocusIn>', self._schedule_opacity_restore, add='+')
        self.bind('<Map>', self._schedule_opacity_restore, add='+')
        self.after_idle(self._schedule_opacity_restore)

    def _schedule_opacity_restore(self, event=None):
        # Отложенный вызов не вмешивается в синхронное обновление DPI в CTk.
        if self.tk.call('tk', 'windowingsystem') != 'win32':
            return
        if self._opacity_restore_job is not None:
            self.after_cancel(self._opacity_restore_job)
        self._opacity_restore_job = self.after(150, self._restore_opacity)

    def _restore_opacity(self):
        self._opacity_restore_job = None
        try:
            if self.winfo_exists() and self.state() != 'iconic':
                self.attributes('-alpha', 1.0)
        except tk.TclError:
            # Окно могло закрыться до исполнения отложенного события.
            pass

    def _build_shell(self):
        sidebar = ctk.CTkFrame(self, width=188, fg_color=SIDEBAR,
                              corner_radius=0, border_width=0)
        sidebar.pack(side='left', fill='y')
        sidebar.pack_propagate(False)
        with Image.open(resource_path('icon.ico')) as source_icon:
            logo = source_icon.convert('RGBA')
        self.sidebar_logo = ctk.CTkImage(light_image=logo, dark_image=logo, size=(64, 64))
        ctk.CTkLabel(sidebar, text='', image=self.sidebar_logo, width=64, height=64,
                     fg_color='transparent').pack(anchor='w', padx=22, pady=(26, 12))
        self.label(sidebar, 'OSINT ANALYZER', 15, True).pack(anchor='w', padx=22)
        self.label(sidebar, 'Анализ переписок', 12, color=MUTED).pack(anchor='w', padx=22, pady=(4, 12))
        self.nav_buttons = {}
        for name in ('Совпадения', 'Статистика', 'По файлам', 'Сеть контактов', 'Импорт', 'Документы', 'Аудио', 'Карта событий', 'Поиск по номеру', 'Информация'):
            button = ctk.CTkButton(sidebar, text=name, anchor='w', height=32,
                corner_radius=8, fg_color=SIDEBAR, hover_color=PALE,
                text_color=MUTED, border_width=1, border_color=SIDEBAR,
                font=ctk.CTkFont(family='Segoe UI', size=14),
                command=lambda value=name: self.tabview.set(value))
            button.pack(fill='x', padx=12, pady=2)
            self.nav_buttons[name] = button
        footer = ctk.CTkFrame(sidebar, fg_color='transparent')
        footer.pack(side='bottom', fill='x', padx=22, pady=24)
        ctk.CTkFrame(footer, height=2, fg_color=BORDER).pack(fill='x', pady=(0, 13))
        self.label(footer, 'Локальная обработка', 11, color='#41D9A3').pack(anchor='w')
        self.label(footer, 'Онлайн-поиск — отдельно', 10, color=MUTED).pack(anchor='w', pady=(4, 0))
        self.workspace = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        self.workspace.pack(side='left', fill='both', expand=True)

    def _mark_section(self, selected):
        extra = selected in ('Документы', 'Аудио', 'Карта событий', 'Поиск по номеру')
        if hasattr(self, 'chat_metrics_row'):
            widgets = (self.chat_actions, self.chat_drop, self.progress, self.chat_metrics_row)
            if not hasattr(self, 'chat_pack_options'):
                self.chat_pack_options = [widget.pack_info() for widget in widgets]
            for widget, options in zip(widgets, self.chat_pack_options):
                if extra:
                    widget.pack_forget()
                elif not widget.winfo_manager():
                    restored = dict(options)
                    if widget is not self.chat_actions:
                        restored['before'] = self.tabview
                    widget.pack(**restored)
        for name, button in self.nav_buttons.items():
            active = name == selected
            button.configure(fg_color='#103554' if active else SIDEBAR,
                             border_color='#267BA3' if active else SIDEBAR,
                             text_color=NAVY if active else MUTED)

    def card(self, parent, **kwargs):
        return ctk.CTkFrame(parent, fg_color=WHITE, border_color=BORDER,
                           border_width=1, corner_radius=12, **kwargs)

    def label(self, parent, text, size=13, bold=False, color=INK, **kwargs):
        return ctk.CTkLabel(parent, text=text, text_color=color,
                           font=ctk.CTkFont(family='Segoe UI', size=size,
                                          weight='bold' if bold else 'normal'), **kwargs)

    def button(self, parent, text, command, secondary=False, **kwargs):
        return ctk.CTkButton(parent, text=text, command=command,
                            fg_color=PALE if secondary else ACCENT,
                            hover_color='#1A3E61' if secondary else HOVER,
                            text_color=INK, text_color_disabled='#657F98',
                            border_color=BORDER if secondary else '#2697DA',
                            border_width=1, corner_radius=8,
                            height=36, font=ctk.CTkFont(family='Segoe UI', size=13), **kwargs)

    def _build_header(self):
        header = ctk.CTkFrame(self.workspace, fg_color='#0A1D33', border_width=1,
                             border_color='#215B7F', corner_radius=14)
        header.pack(fill='x', padx=20, pady=(18, 10))
        top = ctk.CTkFrame(header, fg_color='transparent')
        top.pack(fill='x', padx=20, pady=(13, 0))
        self.label(top, APP_NAME, 23, True, INK).pack(side='left')
        self.label(top, 'ЛОКАЛЬНАЯ АНАЛИТИКА', 10, color=NAVY).pack(side='right')
        actions = ctk.CTkFrame(header, fg_color='transparent')
        actions.pack(fill='x', padx=20, pady=(7, 13))
        self.chat_actions = actions
        self.load_btn = self.button(actions, 'Загрузить чаты', self.load_multiple_files, width=165)
        self.load_btn.pack(side='left', padx=(0, 8))
        self.report_btn = self.button(actions, 'HTML-отчёт', self.report_dialog, True, width=130)
        self.report_btn.pack(side='left', padx=(0, 8))
        self.demo_btn = self.button(actions, 'Демонстрация', self.load_demo, True, width=140)
        self.demo_btn.pack(side='left')
        drop = self.card(self.workspace, height=42)
        self.chat_drop = drop
        drop.configure(border_color='#205275')
        drop.pack(fill='x', padx=20, pady=(0, 6))
        drop.pack_propagate(False)
        ctk.CTkFrame(drop, width=3, corner_radius=0, fg_color=NAVY).pack(side='left', fill='y', padx=(1, 0), pady=8)
        prompt = self.label(drop, 'Перетащите экспорты WhatsApp (.txt) сюда', 13, color=MUTED)
        prompt.pack(side='left', padx=16)
        for widget in (drop, prompt):
            widget.drop_target_register(DND_FILES)
            widget.dnd_bind('<<Drop>>', self.on_drop)
        self.progress = ctk.CTkProgressBar(self.workspace, height=3, fg_color='#10243B', progress_color=NAVY)
        self.progress.pack(fill='x', padx=22)
        self.progress.set(0)

    def _build_metrics(self):
        row = ctk.CTkFrame(self.workspace, fg_color=BG)
        row.pack(fill='x', padx=20, pady=(9, 12))
        self.chat_metrics_row = row
        self.metrics = {}
        for col, title in enumerate(('Файлы', 'Сообщения', 'Участники', 'Совпадения', 'Уровень угрозы')):
            row.grid_columnconfigure(col, weight=1, uniform='metric')
            card = self.card(row)
            card.grid(row=0, column=col, sticky='ew', padx=(0 if col == 0 else 5, 0 if col == 4 else 5))
            accent = (NAVY, '#599FFF', '#42DDB2', '#B398FF', '#F4CD68')[col]
            ctk.CTkFrame(card, height=2, corner_radius=0, fg_color=accent).pack(fill='x', padx=14, pady=(8, 0))
            self.label(card, title, 11, color=MUTED).pack(anchor='w', padx=14, pady=(5, 0))
            value = self.label(card, '0', 17 if col == 4 else 25, True, accent)
            value.pack(anchor='w', padx=14, pady=(0, 7))
            self.metrics[title] = value

    def _style_table(self):
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('Data.Treeview', background=WHITE, foreground=INK,
                        fieldbackground=WHITE, rowheight=36, font=('Segoe UI', 10),
                        borderwidth=0, lightcolor=WHITE, darkcolor=WHITE)
        style.configure('Data.Treeview.Heading', background='#122C46', foreground='#BEEBFF',
                        font=('Segoe UI', 10, 'bold'), padding=(9, 11), relief='flat',
                        bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER)
        style.map('Data.Treeview', background=[('selected', '#174D76')],
                  foreground=[('selected', '#FFFFFF')])
        style.map('Data.Treeview.Heading', background=[('active', '#1B3B5B')])
        for orientation in ('Vertical', 'Horizontal'):
            name = 'Neon.' + orientation + '.TScrollbar'
            style.configure(name, troughcolor=BG, background='#284D70',
                            bordercolor=BG, arrowcolor=MUTED, lightcolor='#284D70', darkcolor='#284D70')
            style.map(name, background=[('active', '#3F7FAA'), ('pressed', ACCENT)])

    def table(self, parent, columns):
        frame = self.card(parent)
        frame.pack(fill='both', expand=True, padx=10, pady=8)
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        tree = ttk.Treeview(frame, columns=[x[0] for x in columns], show='headings',
                            selectmode='browse', style='Data.Treeview')
        for key, title, width in columns:
            tree.heading(key, text=title)
            tree.column(key, width=width, minwidth=55, stretch=False)
        tree.grid(row=0, column=0, sticky='nsew', padx=(1, 0), pady=(1, 0))
        y = ttk.Scrollbar(frame, orient='vertical', command=tree.yview, style='Neon.Vertical.TScrollbar')
        y.grid(row=0, column=1, sticky='ns')
        x = ttk.Scrollbar(frame, orient='horizontal', command=tree.xview, style='Neon.Horizontal.TScrollbar')
        x.grid(row=1, column=0, sticky='ew')
        tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        tree.tag_configure('even', background=WHITE)
        tree.tag_configure('odd', background=PALE)
        return tree

    def _build_findings(self):
        parent = self.tabs['Совпадения']
        filters = self.card(parent)
        filters.configure(border_color='#27658A', border_width=1)
        filters.pack(fill='x', padx=10, pady=(10, 0))
        for col in range(3):
            filters.grid_columnconfigure(col, weight=1, uniform='filter')
        self.search_var = tk.StringVar()
        self.category_var = tk.StringVar(value='Все категории')
        self.sender_var = tk.StringVar(value='Все участники')
        self.file_var = tk.StringVar(value='Все файлы')
        entry = ctk.CTkEntry(filters, textvariable=self.search_var, height=36,
                            placeholder_text='Поиск по найденным сообщениям, участнику, слову или правилу',
                            fg_color=PALE, border_color=BORDER, text_color=INK)
        self.label(filters, 'Поиск по тексту найденного сообщения, участнику, слову или ID правила',
                   12, color=MUTED).grid(row=0, column=0, columnspan=4, sticky='w', padx=10, pady=(8, 0))
        entry.grid(row=1, column=0, columnspan=3, sticky='ew', padx=10, pady=8)
        self.button(filters, 'Сбросить', self.reset_filters, True, width=105).grid(row=1, column=3, padx=10)
        self.filter_menus = []
        for col, variable in enumerate((self.category_var, self.sender_var, self.file_var)):
            menu = ctk.CTkOptionMenu(filters, variable=variable, values=[variable.get()],
                                     dynamic_resizing=False, fg_color='#132C46', text_color=INK,
                                     button_color='#1B4669', button_hover_color='#21608C',
                                     dropdown_fg_color=WHITE, dropdown_text_color=INK,
                                     dropdown_hover_color='#132C46',
                                     command=lambda _: self.apply_filters())
            menu.grid(row=2, column=col, sticky='ew', padx=10, pady=(0, 10))
            self.filter_menus.append(menu)
        self.search_var.trace_add('write', self.schedule_search)
        self.tree = self.table(parent, [('file', 'Файл', 175), ('date', 'Дата', 90),
            ('time', 'Время', 70), ('sender', 'Участник', 150), ('rule_id', 'Правило', 75),
            ('word', 'Совпадение', 170), ('review_status', 'Проверка контекста', 255),
            ('category', 'Категория', 250), ('threat_level', 'Уровень угрозы', 160)])
        self.category_icons = {}
        for category in THREAT_PATTERNS:
            icon = tk.PhotoImage(master=self, width=10, height=10)
            icon.put(category['color'], to=(0, 0, 10, 10))
            self.category_icons[category['category']] = icon
        self.tree.configure(show='tree headings')
        self.tree.column('#0', width=28, minwidth=28, stretch=False)
        self.tree.heading('#0', text='')
        self.tree.bind('<Double-1>', self.open_context)
        self.tree.bind('<Return>', self.open_context)
        footer = ctk.CTkFrame(parent, fg_color=WHITE)
        footer.pack(fill='x', padx=10, pady=(0, 8))
        self.count_label = self.label(footer, '', color=MUTED)
        self.count_label.pack(side='left')
        self.next_btn = self.button(footer, 'Далее', lambda: self.change_page(1), True, width=75)
        self.next_btn.pack(side='right', padx=4)
        self.prev_btn = self.button(footer, 'Назад', lambda: self.change_page(-1), True, width=75)
        self.prev_btn.pack(side='right', padx=4)
        self.button(footer, 'Контекст сообщения', self.open_context, width=145).pack(side='right', padx=8)

    def _build_network(self):
        parent = self.tabs['Сеть контактов']
        self.label(parent, 'Совместное участие в чатах', 19, True, NAVY).pack(anchor='w', padx=22, pady=(25, 8))
        self.label(parent, 'Связь обозначает наличие сообщений участников в одном экспорте.', color=MUTED).pack(anchor='w', padx=22)
        self.button(parent, 'Открыть сеть контактов', self.open_safe_graph, width=230).pack(anchor='w', padx=22, pady=22)

    def _build_info(self):
        parent = self.tabs['Информация']
        self.label(parent, APP_NAME, 22, True, NAVY).pack(anchor='w', padx=22, pady=(24, 15))
        text = (
            'Возможности\n\n'
            'Программа читает экспортированные переписки WhatsApp и анализирует их\n'
            'на признаки подозрительной или опасной деятельности.\n\n'
            'Находит ключевые выражения, сленг и кодовые слова,\n'
            'которыми может маскироваться смысл сообщений, по встроенной базе.\n\n'
            'Учитывает ближайшие реплики, бытовые обороты и выражения намерения.\n'
            'Показывает уровень угрозы и контекст найденных сообщений.\n'
            'Поддерживает поиск, фильтры, сеть контактов и формирование отчёта.\n\n'
            'Автоанализ и поиск по TXT, DOCX и PDF; офлайн-расшифровка аудио.\n'
            'Карта событий: координаты, даты, источники и локальные карты MBTiles.\n\n'
            'Чаты, документы и аудио обрабатываются локально.\n'
            'Поиск по номеру через API отправляет введённый запрос выбранным сервисам.'
        )
        self.label(parent, text, 15, justify='left').pack(anchor='w', padx=22)

    def load_multiple_files(self):
        if self.busy:
            return
        paths = filedialog.askopenfilenames(title='Выберите экспорты WhatsApp', filetypes=[('Текстовые экспорты', '*.txt')])
        if paths:
            self.process_all_files(paths)

    def on_drop(self, event):
        try:
            if not self.busy:
                self.process_all_files(self.tk.splitlist(event.data))
        finally:
            self._schedule_opacity_restore()
        return event.action

    def process_all_files(self, paths):
        if self.busy:
            return
        self.busy = True
        self.load_btn.configure(state='disabled')
        self.demo_btn.configure(state='disabled')
        self.report_btn.configure(state='disabled')
        self.progress.configure(mode='indeterminate')
        self.progress.start()
        self.status.configure(text='Чтение файлов и анализ…')
        def worker():
            results, rejected, seen = [], [], set()
            try:
                for index, path in enumerate(paths):
                    name = Path(path).name
                    try:
                        if Path(path).suffix.lower() != '.txt':
                            raise ValueError('Поддерживаются файлы .txt')
                        text, encoding, digest = self.analyzer.read_file(path)
                        if digest in seen:
                            rejected.append((name, 'Дубликат содержимого; повторно не анализировался'))
                            continue
                        seen.add(digest)
                        results.append(self.analyzer.analyze(text, name, encoding, digest, str(index)))
                    except (OSError, ValueError) as exc:
                        rejected.append((name, str(exc)))
                self.events.put(('done', results, rejected))
            except Exception as exc:
                self.events.put(('error', str(exc)))
        threading.Thread(target=worker, daemon=True).start()
        self.after(100, self.poll_analysis)

    def poll_analysis(self):
        try:
            event = self.events.get_nowait()
        except queue.Empty:
            self.after(100, self.poll_analysis)
            return
        self.busy = False
        self.progress.stop()
        self.progress.configure(mode='determinate')
        self.progress.set(0)
        self.load_btn.configure(state='normal')
        self.demo_btn.configure(state='normal')
        if event[0] == 'error':
            self.report_btn.configure(state='normal' if self.all_results else 'disabled')
            self.status.configure(text='Анализ завершился с ошибкой.')
            messagebox.showerror('Ошибка анализа', event[1])
            return
        self.all_results, self.rejected_files = event[1], event[2]
        self.refresh_results()
        if self.rejected_files or any(r['import_info']['issues'] or not r['total_messages'] for r in self.all_results):
            self.tabview.set('Импорт')

    def load_demo(self):
        if self.busy:
            return
        self.all_results = [self.analyzer.analyze(text, name, source_id=f'demo-{i}', demo=True)
                            for i, (name, text) in enumerate(self.analyzer.demo_chats())]
        self.rejected_files = []
        self.refresh_results()
        self.tabview.set('Совпадения')

    def refresh_results(self):
        self.finding_items = [f for r in self.all_results for f in r['findings']]
        level = self.analyzer.threat_level(self.finding_items)
        values = [len(self.all_results), sum(r['total_messages'] for r in self.all_results),
                  len({c for r in self.all_results for c in r['contacts']}), len(self.finding_items),
                  level['name'] if any(r['total_messages'] for r in self.all_results) else 'Не определён']
        for value, label in zip(values, self.metrics.values()):
            label.configure(text=str(value))
        self.metrics['Уровень угрозы'].configure(text_color=LEVEL_COLORS.get(values[-1], MUTED))
        for menu, default, key in zip(self.filter_menus,
                ('Все категории', 'Все участники', 'Все файлы'), ('category', 'sender', 'file')):
            menu.configure(values=[default] + sorted({f[key] for f in self.finding_items}, key=str.casefold))
        self.reset_filters()
        self.update_stats()
        self.update_files()
        self.update_import()
        self.report_btn.configure(state='normal' if self.all_results and not self.busy else 'disabled')
        demo = any(r['demo'] for r in self.all_results)
        self.status.configure(text=('ДЕМОНСТРАЦИЯ · Все переписки вымышлены.  ' if demo else '') +
            ('Найденные выражения требуют проверки контекста.' if self.all_results else
             'Загрузите текстовые экспорты WhatsApp или откройте демонстрацию.'))

    def schedule_search(self, *_):
        if self.pending_search is not None:
            self.after_cancel(self.pending_search)
        self.pending_search = self.after(200, self.apply_filters)

    def reset_filters(self):
        self.search_var.set('')
        self.category_var.set('Все категории')
        self.sender_var.set('Все участники')
        self.file_var.set('Все файлы')
        self.apply_filters()

    def apply_filters(self):
        if self.pending_search is not None:
            self.after_cancel(self.pending_search)
            self.pending_search = None
        self.filtered_items = self.analyzer.filter_findings(
            self.finding_items, self.search_var.get(),
            None if self.category_var.get() == 'Все категории' else self.category_var.get(),
            None if self.sender_var.get() == 'Все участники' else self.sender_var.get(),
            None if self.file_var.get() == 'Все файлы' else self.file_var.get())
        self.page = 0
        self.render_findings()

    def change_page(self, delta):
        last = max(0, (len(self.filtered_items)-1)//self.page_size)
        self.page = min(last, max(0, self.page+delta))
        self.render_findings()

    def render_findings(self):
        self.tree.delete(*self.tree.get_children())
        start = self.page*self.page_size
        for i, f in enumerate(self.filtered_items[start:start+self.page_size], start):
            self.tree.insert('', 'end', iid=str(i), image=self.category_icons[f['category']], values=[f[k] for k in
                ('file', 'date', 'time', 'sender', 'rule_id', 'word', 'review_status', 'category', 'threat_level')],
                tags=('odd' if i % 2 else 'even',))
        total = len(self.filtered_items)
        self.count_label.configure(text=f'Совпадений: {total} из {len(self.finding_items)}  ·  '
            f'{start+1 if total else 0}–{min(start+self.page_size, total)}')
        self.prev_btn.configure(state='normal' if self.page else 'disabled')
        self.next_btn.configure(state='normal' if start+self.page_size < total else 'disabled')
        self.tree.yview_moveto(0)

    def open_context(self, event=None):
        selected = self.tree.selection()
        if not selected:
            return
        finding = self.filtered_items[int(selected[0])]
        result = next(r for r in self.all_results if r['source_id'] == finding['source_id'])
        window = ctk.CTkToplevel(self)
        apply_window_icon(window)
        window.title('Контекст и объяснение | '+APP_NAME)
        window.geometry('900x650')
        window.transient(self)
        window.configure(fg_color=BG)
        self.label(window, f'{finding["rule_id"]} · {finding["rule_title"]}', 19, True, NAVY).pack(anchor='w', padx=20, pady=(20, 5))
        self.label(window, finding['review_status'], 15, True, '#F4CD68').pack(anchor='w', padx=20, pady=5)
        self.label(window, finding['reason'], wraplength=840, justify='left').pack(anchor='w', padx=20, pady=5)
        self.label(window, f'{finding["file"]} · строка {finding["line"]} · ближайшие реплики в пределах 15 минут', color=MUTED).pack(anchor='w', padx=20, pady=5)
        box = tk.Text(window, wrap='word', bg=WHITE, fg=INK, font=('Segoe UI', 12),
                      relief='flat', bd=0, highlightthickness=1, highlightbackground=BORDER,
                      insertbackground=INK, selectbackground='#174D76', selectforeground=INK, padx=16, pady=16)
        box.pack(fill='both', expand=True, padx=20, pady=15)
        box.tag_configure('hit', background='#624C24', foreground=INK)
        box.tag_configure('heading', foreground=NAVY, font=('Segoe UI', 11, 'bold'))
        for msg in self.analyzer.context(result, finding):
            box.insert('end', f'{msg["date"]} {msg["time"]} | {msg["sender"]}\n', 'heading')
            begin = box.index('end-1c')
            box.insert('end', msg['text']+'\n\n')
            if msg['index'] == finding['message_index']:
                for a, b in finding['spans']:
                    # Длину вычисляет сам Tcl: одинаковая подсветка в Tcl 8 и 9.
                    start = int(box.tk.call('string', 'length', msg['text'][:a]))
                    end = int(box.tk.call('string', 'length', msg['text'][:b]))
                    box.tag_add('hit', f'{begin}+{start}c', f'{begin}+{end}c')
        box.configure(state='disabled')

    def update_stats(self):
        parent = self.tabs['Статистика']
        for widget in parent.winfo_children():
            widget.destroy()
        self.label(parent, 'Срабатывания правил по категориям', 18, True, NAVY).pack(anchor='w', padx=18, pady=(15, 0))
        tree = self.table(parent, [('category', 'Категория', 470), ('count', 'Совпадения', 160), ('level', 'Уровень угрозы', 180)])
        for i, category in enumerate(THREAT_PATTERNS):
            name = category['category']
            count = sum(r['stats'][name]['count'] for r in self.all_results)
            level = self.analyzer.threat_level([f for f in self.finding_items if f['category'] == name])['name']
            tree.insert('', 'end', values=(name, count, level), tags=('odd' if i % 2 else 'even',))
        self.label(parent, 'Показан наиболее высокий уровень среди найденных выражений категории.', color=MUTED).pack(anchor='w', padx=18, pady=8)

    def update_files(self):
        parent = self.tabs['По файлам']
        for widget in parent.winfo_children():
            widget.destroy()
        tree = self.table(parent, [('file', 'Файл', 350), ('messages', 'Сообщения', 120),
            ('contacts', 'Участники', 110), ('hits', 'Совпадения', 120), ('level', 'Уровень угрозы', 160)])
        for i, r in enumerate(self.all_results):
            tree.insert('', 'end', values=(r['filename'], r['total_messages'], len(r['contacts']),
                r['total_findings'], r['threat_level']['name']), tags=('odd' if i % 2 else 'even',))

    def update_import(self):
        parent = self.tabs['Импорт']
        for widget in parent.winfo_children():
            widget.destroy()
        self.label(parent, 'Дата: день/месяц/год или год-месяц-день. Строки без заголовка после сообщения — продолжение.',
                   color=MUTED).pack(anchor='w', padx=15, pady=(12, 0))
        box = ctk.CTkTextbox(parent, fg_color=PALE, border_width=1, border_color=BORDER,
                             text_color=INK, wrap='word')
        box.pack(fill='both', expand=True, padx=12, pady=12)
        for r in self.all_results:
            info = r['import_info']
            box.insert('end', f'{r["filename"]}\nКодировка: {r["encoding"]} · Строк: {info["lines"]} · '
                f'Сообщений: {r["total_messages"]} · Продолжений: {info["continuation"]} · '
                f'Системных: {info["system"]} · Проблемных: {len(info["issues"])}\n')
            if r['encoding'] == 'cp1251':
                box.insert('end', 'Кодировка cp1251 выбрана после проверки UTF-8. Проверьте читаемость текста.\n')
            if not r['total_messages']:
                box.insert('end', 'Внимание: сообщений не распознано. Проверьте формат экспорта.\n')
            for issue in info['issues']:
                box.insert('end', f'Строка {issue["line"]}: {issue["reason"]}\n{issue["text"]}\n')
            box.insert('end', '\n')
        for name, reason in self.rejected_files:
            box.insert('end', f'Не загружен: {name}\n{reason}\n\n')
        if not self.all_results and not self.rejected_files:
            box.insert('end', 'Файлы ещё не загружены.')
        box.configure(state='disabled')

    def report_dialog(self):
        if not self.all_results or self.busy:
            return
        self.apply_filters()
        # Снимок данных защищает отчёт от последующей загрузки другого набора.
        results = list(self.all_results)
        rejected_files = list(self.rejected_files)
        all_findings = list(self.finding_items)
        filtered = list(self.filtered_items)
        window = ctk.CTkToplevel(self)
        apply_window_icon(window)
        window.title('Экспорт отчёта | '+APP_NAME)
        window.geometry('680x460')
        window.configure(fg_color=BG)
        window.transient(self)
        scope = tk.StringVar(value='Все совпадения')
        self.label(window, 'Состав отчёта', 18, True, NAVY).pack(anchor='w', padx=20, pady=(20, 10))
        ctk.CTkOptionMenu(window, variable=scope, values=['Все совпадения', 'Текущая выборка'],
                          fg_color=ACCENT, button_color=ACCENT, text_color=INK, dropdown_fg_color=WHITE, dropdown_text_color=INK,
                          dropdown_hover_color=PALE).pack(anchor='w', padx=20)
        self.label(window, 'Комментарий аналитика').pack(anchor='w', padx=20, pady=(15, 5))
        note = ctk.CTkTextbox(window, fg_color=WHITE, text_color=INK, border_width=1, border_color=BORDER)
        note.pack(fill='both', expand=True, padx=20, pady=5)
        def save():
            path = filedialog.asksaveasfilename(parent=window, title='Сохранить HTML-отчёт',
                    defaultextension='.html', initialfile='Whatsapp_Osint_report.html', filetypes=[('HTML', '*.html')])
            if not path:
                return
            try:
                self.analyzer.write_report(path, results, all_findings if scope.get() == 'Все совпадения' else filtered,
                                           note.get('1.0', 'end-1c'), scope.get(), rejected_files)
            except OSError as exc:
                messagebox.showerror('Не удалось сохранить', str(exc), parent=window)
                return
            messagebox.showinfo('Отчёт сохранён', 'Откройте HTML-файл в браузере. Для печати или PDF нажмите Ctrl+P.', parent=window)
            window.destroy()
        self.button(window, 'Сохранить HTML', save, width=170).pack(anchor='e', padx=20, pady=18)

    def open_safe_graph(self):
        if not self.all_results:
            messagebox.showinfo('Сеть контактов', 'Сначала загрузите переписки.')
            return
        levels, edges = {}, set()
        for r in self.all_results:
            for name, value in r['sender_threat'].items():
                levels[name] = self.analyzer.highest_level((levels.get(name, 'Низкий'), value))['name']
            names = r['contacts']
            edges.update(tuple(sorted((a, b))) for i, a in enumerate(names) for b in names[i+1:])
        if not levels:
            messagebox.showinfo('Сеть контактов', 'Участники не найдены.')
            return
        window = tk.Toplevel(self)
        apply_window_icon(window)
        window.title('Сеть контактов | '+APP_NAME)
        window.geometry('1100x760')
        window.configure(bg=BG)
        tk.Label(window, text='Совместное участие в чатах · узлы можно перемещать мышью',
                 bg=BG, fg=NAVY, font=('Segoe UI', 13, 'bold')).pack(pady=12)
        canvas = tk.Canvas(window, bg=WHITE, highlightbackground=BORDER, highlightthickness=1)
        canvas.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        names = sorted(levels, key=str.casefold)
        pos = {name: [530+265*math.cos(2*math.pi*i/len(names)), 320+265*math.sin(2*math.pi*i/len(names))]
               for i, name in enumerate(names)}
        def draw():
            canvas.delete('all')
            for a, b in sorted(edges):
                canvas.create_line(*pos[a], *pos[b], fill='#16496E', width=4)
                canvas.create_line(*pos[a], *pos[b], fill='#4095BD', width=1)
            for name in names:
                x, y = pos[name]
                color = LEVEL_COLORS.get(levels[name], NAVY)
                canvas.create_oval(x-46, y-46, x+46, y+46, fill='#102B43', outline='#194462', width=2)
                canvas.create_oval(x-41, y-41, x+41, y+41, outline='#2B6382', width=2)
                canvas.create_oval(x-38, y-38, x+38, y+38, fill=PALE, outline=color, width=2)
                canvas.create_text(x, y, text=name, width=72, fill=INK, font=('Segoe UI', 9, 'bold'))
        dragged = [None]
        def press(event):
            dragged[0] = next((name for name in reversed(names)
                               if (pos[name][0]-event.x)**2+(pos[name][1]-event.y)**2 <= 38**2), None)
        def move(event):
            if dragged[0] is not None:
                pos[dragged[0]] = [event.x, event.y]
                draw()
        canvas.bind('<Button-1>', press)
        canvas.bind('<B1-Motion>', move)
        canvas.bind('<ButtonRelease-1>', lambda _: dragged.__setitem__(0, None))
        draw()


    def _build_extra_tools(self):
        self.extra_queue = queue.Queue()
        self.extra_busy = set()
        self.document_blocks, self.document_hits, self.document_auto_hits = [], [], []
        self.document_issues = []
        self.audio_segments = []
        self.audio_source = ''
        self.audio_partial = False
        self.audio_cancel = threading.Event()
        self.event_rows = []
        self.event_dirty = False
        self.tiles = None
        self.tile_cache = {}
        self.map_zoom = 3
        self.map_lat, self.map_lon = 48.0, 67.0
        self._build_documents()
        self._build_audio()
        self._build_events()
        self._build_phone()
        self.after(120, self._poll_extra)
        self.protocol('WM_DELETE_WINDOW', self._close_workspace)

    def _toolbar(self, parent):
        row = ctk.CTkFrame(parent, fg_color='transparent')
        row.pack(fill='x', padx=12, pady=(8, 0))
        return row

    def _extra_job(self, key, work):
        if key in self.extra_busy:
            return False
        self.extra_busy.add(key)
        def worker():
            try:
                value = work(lambda kind, data: self.extra_queue.put((key, kind, data)))
                self.extra_queue.put((key, 'done', value))
            except Exception as error:
                self.extra_queue.put((key, 'error', str(error)))
        threading.Thread(target=worker, daemon=True).start()
        return True

    def _poll_extra(self):
        for _ in range(100):
            try:
                key, kind, data = self.extra_queue.get_nowait()
            except queue.Empty:
                break
            if kind in ('done', 'error'):
                self.extra_busy.discard(key)
            if key == 'documents':
                if kind == 'done':
                    self.document_blocks, self.document_auto_hits, issues = data
                    self.document_issues = issues
                    self.doc_mode.set('Автоанализ')
                    self.doc_query.delete(0, 'end')
                    self._search_documents()
                    if issues:
                        self._text_window('Импорт документов', '\n'.join(issues))
                elif kind == 'status':
                    self.doc_status.configure(text=data)
                elif kind == 'error':
                    self.doc_status.configure(text='Ошибка импорта')
                    messagebox.showerror('Документы', data)
            elif key == 'phone':
                if kind == 'done':
                    self._phone_show(data)
                    self.phone_status.configure(text='Завершено. Ошибки отдельных сервисов указаны в результате. Совпадение не устанавливает личность.')
                elif kind == 'error':
                    self.phone_status.configure(text='Запрос не выполнен.')
                    messagebox.showerror('Поиск по номеру', data)
            elif key == 'audio':
                if kind == 'segment':
                    self.audio_segments.append(data)
                    self._render_audio()
                elif kind == 'status':
                    self.audio_status.configure(text=data)
                elif kind == 'done':
                    self.audio_partial = self.audio_cancel.is_set()
                    self.audio_status.configure(text=('Остановлено. Сохранён частичный результат.' if self.audio_partial else 'Расшифровка завершена. Сверьте текст с записью.'))
                elif kind == 'error':
                    self.audio_partial = True
                    self.audio_status.configure(text='Ошибка. Полученные фрагменты можно сохранить.')
                    messagebox.showerror('Расшифровка', data)
        self.after(120, self._poll_extra)

    def _text_window(self, title, text):
        window = ctk.CTkToplevel(self)
        window.title(title)
        window.geometry('900x580')
        apply_window_icon(window)
        box = ctk.CTkTextbox(window, fg_color=BG, text_color=INK, wrap='word')
        box.pack(fill='both', expand=True, padx=15, pady=15)
        box.insert('1.0', text)
        box.configure(state='disabled')
        window.after(100, window.lift)

    def _build_documents(self):
        page = self.tabs['Документы']
        row = self._toolbar(page)
        self.button(row, 'Загрузить документы', self._load_documents).pack(side='left', padx=(0, 8))
        self.button(row, 'Экспорт CSV', self._export_documents, True).pack(side='left')
        self.doc_query = ctk.CTkEntry(page, placeholder_text='Автоанализ: фильтр результатов. Поиск текста: введите слово или фразу.')
        self.doc_query.pack(fill='x', padx=12, pady=8)
        self.doc_query.bind('<Return>', lambda event: self._search_documents())
        row = self._toolbar(page)
        self.doc_mode = ctk.CTkOptionMenu(row, values=['Автоанализ', 'Поиск текста'], command=lambda value: self._search_documents(), fg_color=PALE, width=145)
        self.doc_mode.pack(side='left', padx=(0, 8))
        self.button(row, 'Найти', self._search_documents, width=85).pack(side='left')
        self.doc_status = self.label(row, 'Загрузите документы — автоанализ начнётся сразу.', color=MUTED)
        self.doc_status.pack(side='left', padx=12)
        self.doc_status.configure(wraplength=570, justify='left')
        self.doc_tree = self.table(page, [('file', 'Документ', 190), ('location', 'Место', 100), ('category', 'Категория', 230), ('level', 'Уровень угрозы', 130), ('word', 'Найдено', 200), ('text', 'Фрагмент', 600)])
        self.doc_tree.bind('<Double-1>', self._open_document_hit)

    def _load_documents(self):
        if 'documents' in self.extra_busy:
            return
        paths = filedialog.askopenfilenames(filetypes=[('Документы', '*.txt *.docx *.pdf')])
        if paths:
            self.doc_status.configure(text='Извлечение текста… Новый набор заменит предыдущий.')
            self._extra_job('documents', lambda emit: DocumentSearch.extract_and_analyze(paths, emit))

    def _search_documents(self):
        query = self.doc_query.get().strip()
        automatic = self.doc_mode.get() == 'Автоанализ'
        if automatic:
            self.document_hits = [row for row in self.document_auto_hits if not query or
                query.casefold() in ' '.join(str(row.get(key, '')) for key in
                ('source', 'location', 'excerpt', 'word', 'category', 'reason', 'threat_level')).casefold()]
        else:
            self.document_hits = DocumentSearch.search(self.document_blocks, query)
        self.doc_tree.delete(*self.doc_tree.get_children())
        for i, row in enumerate(self.document_hits[:2000]):
            self.doc_tree.insert('', 'end', iid=str(i), values=(Path(row['source']).name,
                row['location'], row.get('category', 'Поиск текста'), row.get('threat_level', '—'),
                row.get('word', query), row['excerpt']), tags=('odd' if i % 2 else 'even',))
        files = len({row['source'] for row in self.document_blocks})
        if not self.document_blocks:
            text = 'Загрузите документы для автоматического анализа.'
        elif not automatic and not query:
            text = f'Документов с текстом: {files}. Введите слово или переключитесь на «Автоанализ».'
        else:
            text = f'Документов с текстом: {files}. Найдено: {len(self.document_hits)}. Замечаний импорта: {len(self.document_issues)}.'
            text += ' Требуется проверка контекста.' if automatic else ''
            if len(self.document_hits) > 2000:
                text += ' Показаны первые 2000; CSV содержит все.'
        self.doc_status.configure(text=text)

    def _open_document_hit(self, event=None):
        selected = self.doc_tree.selection()
        if selected:
            row = self.document_hits[int(selected[0])]
            self._text_window('Фрагмент документа', f"{row['source']}\n{row['location']}\n{row.get('category', 'Поиск текста')}\n{row.get('reason', '')}\n\nНайденный фрагмент:\n{row['excerpt']}\n\nИсходный блок:\n{row['text']}")

    def _export_documents(self):
        if not self.document_hits:
            messagebox.showinfo('Документы', 'Сначала выполните поиск.')
            return
        path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV', '*.csv')])
        if path:
            try:
                write_table_csv(path, self.document_hits, [('source', 'Источник'), ('location', 'Место'), ('category', 'Категория'), ('threat_level', 'Уровень угрозы'), ('word', 'Найдено'), ('review_status', 'Статус'), ('reason', 'Объяснение'), ('excerpt', 'Фрагмент'), ('text', 'Исходный текст')])
            except Exception as error:
                messagebox.showerror('Экспорт', str(error))

    def _build_audio(self):
        page = self.tabs['Аудио']
        row = self._toolbar(page)
        self.button(row, 'Выбрать запись', self._select_audio).pack(side='left', padx=(0, 8))
        self.audio_file_label = self.label(row, 'Файл не выбран', color=MUTED)
        self.audio_file_label.pack(side='left')
        row = self._toolbar(page)
        self.model_path = ctk.CTkEntry(row)
        self.model_path.pack(side='left', fill='x', expand=True, padx=(0, 8))
        self.model_path.insert(0, str(LocalTranscriber.default_model_path()))
        self.button(row, 'Папка модели', self._select_model, True).pack(side='left')
        row = self._toolbar(page)
        self.audio_language = ctk.CTkOptionMenu(row, values=['Авто', 'Русский', 'Қазақша', 'English'], fg_color=PALE)
        self.audio_language.pack(side='left', padx=(0, 8))
        self.button(row, 'Расшифровать', self._start_audio).pack(side='left', padx=(0, 8))
        self.button(row, 'Остановить', self.audio_cancel.set, True, width=110).pack(side='left', padx=(0, 8))
        self.button(row, 'Сохранить', self._save_audio, True, width=110).pack(side='left')
        self.audio_status = self.label(page, 'Офлайн. Сначала загрузите модель через DOWNLOAD_MODEL.bat.', color=MUTED)
        self.audio_status.pack(anchor='w', padx=12, pady=6)
        self.audio_query = ctk.CTkEntry(page, placeholder_text='Поиск в расшифровке — Enter')
        self.audio_query.pack(fill='x', padx=12)
        self.audio_query.bind('<Return>', lambda event: self._render_audio())
        self.audio_tree = self.table(page, [('start', 'Начало', 100), ('end', 'Конец', 100), ('text', 'Распознанный текст', 780)])
        self.audio_tree.bind('<Double-1>', self._open_audio_segment)

    def _select_audio(self):
        if 'audio' in self.extra_busy:
            return
        path = filedialog.askopenfilename(filetypes=[('Аудиозаписи', '*.wav *.mp3 *.m4a *.ogg *.opus *.flac *.aac *.mp4'), ('Все файлы', '*.*')])
        if path:
            if self.audio_segments and not messagebox.askyesno('Новая запись', 'Очистить текущую расшифровку? Сохраните её заранее, если она нужна.'):
                return
            self.audio_source = path
            self.audio_segments = []
            self._render_audio()
            self.audio_file_label.configure(text=Path(path).name)

    def _select_model(self):
        path = filedialog.askdirectory(title='Папка локальной модели faster-whisper')
        if path:
            self.model_path.delete(0, 'end')
            self.model_path.insert(0, path)

    def _start_audio(self):
        if 'audio' in self.extra_busy:
            return
        if not self.audio_source:
            messagebox.showinfo('Аудио', 'Выберите аудиозапись.')
            return
        if self.audio_segments and not messagebox.askyesno('Расшифровка', 'Заменить текущую расшифровку новым результатом?'):
            return
        source, model = self.audio_source, self.model_path.get().strip()
        language = {'Авто': None, 'Русский': 'ru', 'Қазақша': 'kk', 'English': 'en'}[self.audio_language.get()]
        self.audio_segments = []
        self.audio_partial = True
        self.audio_cancel.clear()
        self._render_audio()
        self.audio_status.configure(text='Подготовка…')
        self._extra_job('audio', lambda emit: LocalTranscriber.run(source, model, language, self.audio_cancel, emit))

    def _render_audio(self):
        query = self.audio_query.get().casefold().strip()
        self.audio_tree.delete(*self.audio_tree.get_children())
        for i, row in enumerate(self.audio_segments):
            if query in row['text'].casefold():
                self.audio_tree.insert('', 'end', iid=str(i), values=(LocalTranscriber.stamp(row['start']), LocalTranscriber.stamp(row['end']), row['text']))

    def _open_audio_segment(self, event=None):
        selected = self.audio_tree.selection()
        if selected:
            row = self.audio_segments[int(selected[0])]
            self._text_window('Фрагмент записи', f"{self.audio_source}\n{LocalTranscriber.stamp(row['start'])} — {LocalTranscriber.stamp(row['end'])}\n\n{row['text']}")

    def _save_audio(self):
        if not self.audio_segments:
            messagebox.showinfo('Аудио', 'Нет распознанных фрагментов.')
            return
        path = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[('Текст', '*.txt'), ('Субтитры SRT', '*.srt')])
        if path:
            try:
                LocalTranscriber.save(path, list(self.audio_segments), self.audio_source, self.audio_partial or 'audio' in self.extra_busy)
            except Exception as error:
                messagebox.showerror('Экспорт', str(error))

    def _build_events(self):
        page = self.tabs['Карта событий']
        row = self._toolbar(page)
        for title, command in [('Добавить', self._event_dialog), ('Изменить', self._edit_event), ('Удалить', self._delete_event), ('Открыть JSON', self._load_events), ('Сохранить JSON', self._save_events)]:
            self.button(row, title, command, True, width=120).pack(side='left', padx=(0, 5))
        row = self._toolbar(page)
        self.button(row, 'Карта MBTiles', self._load_tiles, True, width=135).pack(side='left', padx=(0, 8))
        self.button(row, '+', lambda: self._zoom_map(1), True, width=35).pack(side='left', padx=(0, 5))
        self.button(row, '−', lambda: self._zoom_map(-1), True, width=35).pack(side='left')
        self.event_query = ctk.CTkEntry(row, placeholder_text='Поиск по названию, дате, источнику — Enter')
        self.event_query.pack(side='left', fill='x', expand=True, padx=10)
        self.event_query.bind('<Return>', lambda event: self._render_events())
        self.map_status = self.label(page, 'Без подложки: координатная сетка. Загрузите растровый MBTiles. Двойной щелчок — событие.', 11, color=MUTED)
        self.map_status.pack(fill='x', padx=12, pady=4)
        split = tk.PanedWindow(page, orient='vertical', bg=BORDER, sashwidth=6, bd=0)
        split.pack(fill='both', expand=True, padx=12, pady=(0, 10))
        self.map_canvas = tk.Canvas(split, bg=BG, highlightthickness=0, height=240)
        split.add(self.map_canvas, minsize=140, stretch='always')
        bottom = ctk.CTkFrame(split, fg_color=WHITE)
        split.add(bottom, minsize=100, stretch='always')
        self.event_tree = self.table(bottom, [('date', 'Дата', 145), ('title', 'Событие', 230), ('coords', 'Координаты', 190), ('source', 'Источник', 350)])
        self.event_tree.bind('<<TreeviewSelect>>', self._select_event)
        self.event_tree.bind('<Double-1>', lambda event: self._edit_event())
        self.map_canvas.bind('<Configure>', lambda event: self._draw_map())
        self.map_canvas.bind('<ButtonPress-1>', self._map_press)
        self.map_canvas.bind('<B1-Motion>', self._map_drag)
        self.map_canvas.bind('<Double-1>', self._map_add)
        self.map_canvas.bind('<MouseWheel>', lambda event: self._zoom_map(1 if event.delta > 0 else -1))
        self.map_images = []

    def _event_dialog(self, index=None, coords=None):
        old = self.event_rows[index] if index is not None else {}
        window = ctk.CTkToplevel(self)
        window.title('Событие')
        window.geometry('600x610')
        fields = {}
        for key, title in [('title', 'Название'), ('date', 'Дата: ГГГГ-ММ-ДД ЧЧ:ММ (можно оставить пустой)'), ('lat', 'Широта'), ('lon', 'Долгота'), ('source', 'Источник: файл, страница или временная метка'), ('description', 'Описание')]:
            self.label(window, title).pack(anchor='w', padx=20, pady=(10, 2))
            entry = ctk.CTkEntry(window)
            entry.pack(fill='x', padx=20)
            value = old.get(key, '')
            if coords and key in ('lat', 'lon'):
                value = round(coords[0 if key == 'lat' else 1], 6)
            entry.insert(0, str(value))
            fields[key] = entry
        def save():
            try:
                row = EventData.validate({key: entry.get() for key, entry in fields.items()})
            except Exception as error:
                messagebox.showerror('Событие', str(error), parent=window)
                return
            if index is None:
                self.event_rows.append(row)
            else:
                self.event_rows[index] = row
            self.event_dirty = True
            self.map_lat, self.map_lon = row['lat'], row['lon']
            self._render_events()
            window.destroy()
        self.button(window, 'Сохранить событие', save).pack(pady=18)
        window.after(100, window.lift)
        window.grab_set()

    def _edit_event(self):
        selected = self.event_tree.selection()
        if selected:
            self._event_dialog(int(selected[0]))

    def _delete_event(self):
        selected = self.event_tree.selection()
        if selected and messagebox.askyesno('Удаление', 'Удалить выбранное событие из текущего набора?'):
            del self.event_rows[int(selected[0])]
            self.event_dirty = True
            self._render_events()

    def _load_events(self):
        if self.event_dirty and not messagebox.askyesno('События', 'Заменить несохранённый набор событий?'):
            return
        path = filedialog.askopenfilename(filetypes=[('События JSON', '*.json')])
        if path:
            try:
                rows = EventData.load(path)
                self.event_rows, self.event_dirty = rows, False
                if rows:
                    self.map_lat, self.map_lon = rows[0]['lat'], rows[0]['lon']
                self._render_events()
            except Exception as error:
                messagebox.showerror('Импорт событий', str(error))

    def _save_events(self):
        path = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('События JSON', '*.json')])
        if path:
            try:
                EventData.save(path, self.event_rows)
                self.event_dirty = False
                return True
            except Exception as error:
                messagebox.showerror('Сохранение', str(error))
        return False

    def _render_events(self):
        self.event_tree.delete(*self.event_tree.get_children())
        query = self.event_query.get().casefold().strip()
        self.visible_events = [i for i, row in enumerate(self.event_rows) if query in ' '.join(str(v) for v in row.values()).casefold()]
        for i in sorted(self.visible_events, key=lambda i: self.event_rows[i]['date']):
            row = self.event_rows[i]
            self.event_tree.insert('', 'end', iid=str(i), values=(row['date'], row['title'], f"{row['lat']:.5f}, {row['lon']:.5f}", row['source']))
        self._draw_map()

    def _select_event(self, event=None):
        selected = self.event_tree.selection()
        if selected:
            row = self.event_rows[int(selected[0])]
            self.map_lat, self.map_lon = row['lat'], row['lon']
            self._draw_map()

    def _load_tiles(self):
        path = filedialog.askopenfilename(filetypes=[('Растровая офлайн-карта', '*.mbtiles')])
        if not path:
            return
        try:
            tiles = OfflineTiles(path)
            if self.tiles:
                self.tiles.close()
            self.tiles = tiles
            self.tile_cache.clear()
            self.map_zoom = max(tiles.minimum, min(tiles.maximum, self.map_zoom))
            center = tiles.metadata.get('center', '').split(',')
            if len(center) >= 2:
                try:
                    lon, lat = float(center[0]), float(center[1])
                    if math.isfinite(lat) and math.isfinite(lon) and abs(lat) <= 85.05112878 and abs(lon) <= 180:
                        self.map_lat, self.map_lon = lat, lon
                except ValueError:
                    pass
            self.map_status.configure(text=f"{Path(path).name} | {tiles.metadata.get('attribution', 'Локальная карта')}"[:200])
            self._draw_map()
        except Exception as error:
            messagebox.showerror('Карта', str(error))

    def _zoom_map(self, delta):
        low, high = (self.tiles.minimum, self.tiles.maximum) if self.tiles else (0, 18)
        self.map_zoom = max(low, min(high, self.map_zoom + delta))
        self._draw_map()

    def _map_press(self, event):
        self.map_anchor = (event.x, event.y, *EventData.project(self.map_lat, self.map_lon, self.map_zoom))

    def _map_drag(self, event):
        if hasattr(self, 'map_anchor'):
            x, y, cx, cy = self.map_anchor
            self.map_lat, self.map_lon = EventData.unproject(cx - event.x + x, cy - event.y + y, self.map_zoom)
            self._draw_map()

    def _map_add(self, event):
        cx, cy = EventData.project(self.map_lat, self.map_lon, self.map_zoom)
        coords = EventData.unproject(cx + event.x - self.map_canvas.winfo_width()/2, cy + event.y - self.map_canvas.winfo_height()/2, self.map_zoom)
        self._event_dialog(coords=coords)

    def _draw_map(self):
        import io
        canvas = self.map_canvas
        canvas.delete('all')
        self.map_images = []
        width, height = canvas.winfo_width(), canvas.winfo_height()
        cx, cy = EventData.project(self.map_lat, self.map_lon, self.map_zoom)
        left, top = cx-width/2, cy-height/2
        tile_error = False
        for x in range(math.floor(left/256), math.floor((left+width)/256)+1):
            for y in range(math.floor(top/256), math.floor((top+height)/256)+1):
                sx, sy = x*256-left, y*256-top
                canvas.create_rectangle(sx, sy, sx+256, sy+256, outline=BORDER)
                if self.tiles and 0 <= y < 2 ** self.map_zoom:
                    key = (self.map_zoom, x % (2 ** self.map_zoom), y)
                    try:
                        if key not in self.tile_cache:
                            from PIL import Image, ImageTk
                            data = self.tiles.tile(*key)
                            photo = None
                            if data:
                                with Image.open(io.BytesIO(data)) as img:
                                    photo = ImageTk.PhotoImage(img.convert('RGB').resize((256, 256)))
                            if len(self.tile_cache) >= 180:
                                self.tile_cache.pop(next(iter(self.tile_cache)))
                            self.tile_cache[key] = photo
                        photo = self.tile_cache[key]
                        if photo:
                            self.map_images.append(photo)
                            canvas.create_image(sx, sy, anchor='nw', image=photo)
                    except Exception:
                        tile_error = True
        world = 256 * 2 ** self.map_zoom
        for i in getattr(self, 'visible_events', range(len(self.event_rows))):
            row = self.event_rows[i]
            x, y = EventData.project(row['lat'], row['lon'], self.map_zoom)
            x = (x-cx+world/2) % world-world/2+width/2
            y = y-top
            if -20 <= x <= width+20 and -20 <= y <= height+20:
                tag = f'event_{i}'
                canvas.create_oval(x-6, y-6, x+6, y+6, fill=NAVY, outline=INK, width=2, tags=tag)
                canvas.create_text(x+10, y-10, text=row['title'][:45], fill=INK, anchor='w', tags=tag)
                canvas.tag_bind(tag, '<Button-1>', lambda event, idx=i: self.event_tree.selection_set(str(idx)))
        caption = f'Центр: {self.map_lat:.5f}, {self.map_lon:.5f} | Масштаб {self.map_zoom}'
        if tile_error:
            caption += ' | Ошибка чтения тайлов'
        canvas.create_rectangle(0, height-26, width, height, fill=BG, outline='')
        canvas.create_text(10, height-13, text=caption, fill=MUTED, anchor='w')

    def _close_workspace(self):
        if self.event_dirty:
            choice = messagebox.askyesnocancel('События', 'Сохранить изменения карты событий перед выходом?')
            if choice is None or (choice and not self._save_events()):
                return
        if self.extra_busy and not messagebox.askyesno('Обработка', 'Обработка ещё выполняется. Закрыть программу? Несохранённые результаты будут потеряны.'):
            return
        self.audio_cancel.set()
        if self.tiles:
            self.tiles.close()
        self.destroy()


    def _build_phone(self):
        page = self.tabs['Поиск по номеру']
        row = self._toolbar(page)
        self.phone_number = ctk.CTkEntry(row, placeholder_text='Номер: +7…')
        self.phone_number.pack(side='left', fill='x', expand=True, padx=(0, 8))
        self.button(row, 'Проверить локально', self._phone_local).pack(side='left')
        self.label(page, 'Справочные сведения по нумерации. Они не показывают владельца или фактическое местоположение.', 12, color=MUTED).pack(anchor='w', padx=12, pady=6)
        keys = ctk.CTkFrame(page, fg_color=PALE)
        keys.pack(fill='x', padx=12)
        keys.grid_columnconfigure(1, weight=1)
        keys.grid_columnconfigure(3, weight=1)
        self.phone_keys, self.phone_enabled = {}, {}
        import os
        env_names = {'Numverify': 'NUMVERIFY_KEY', 'SerpAPI': 'SERPAPI_KEY', 'GitHub': 'GITHUB_TOKEN', 'OpenCage': 'OPENCAGE_KEY', 'Brave': 'BRAVE_SEARCH_API_KEY'}
        for index, name in enumerate(env_names):
            row, col = divmod(index, 2)
            enabled = tk.BooleanVar(value=False)
            ctk.CTkCheckBox(keys, text=name, variable=enabled, width=115).grid(row=row, column=col*2, padx=8, pady=6)
            entry = ctk.CTkEntry(keys, show='*', placeholder_text='API-ключ')
            entry.grid(row=row, column=col*2+1, sticky='ew', padx=8, pady=6)
            entry.insert(0, os.environ.get(env_names[name], ''))
            self.phone_keys[name], self.phone_enabled[name] = entry, enabled
        self.phone_consent = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(page, text='Разрешаю отправить этот номер выбранным сервисам; для OpenCage — введённое место.', variable=self.phone_consent).pack(anchor='w', padx=12, pady=8)
        row = self._toolbar(page)
        self.button(row, 'Поиск в интернете', self._phone_online).pack(side='left', padx=(0, 8))
        self.button(row, 'Сохранить JSON', self._phone_save, True).pack(side='left')
        row = self._toolbar(page)
        self.phone_place = ctk.CTkEntry(row, placeholder_text='Отдельный поиск места через OpenCage: город, улица, дом')
        self.phone_place.pack(side='left', fill='x', expand=True, padx=(0, 8))
        self.button(row, 'Найти место', self._phone_geocode, True).pack(side='left')
        self.phone_status = self.label(page, 'SerpAPI / Brave: публичные страницы и объявления. Один запрос на выбранный поисковик.', 12, color=MUTED)
        self.phone_status.pack(anchor='w', padx=12, pady=6)
        self.phone_output = ctk.CTkTextbox(page, wrap='word', fg_color=BG, text_color=INK)
        self.phone_output.pack(fill='both', expand=True, padx=12, pady=(0, 12))
        self.phone_output.configure(state='disabled')
        self.phone_result = None

    def _phone_show(self, data):
        import json
        self.phone_result = data
        self.phone_output.configure(state='normal')
        self.phone_output.delete('1.0', 'end')
        if 'sources' in data:
            local = data.get('local', {})
            zones = local.get('timezones', [])
            lines = ['ПОИСК ПУБЛИЧНЫХ УПОМИНАНИЙ', '',
                     'Номер: ' + str(local.get('number', '')),
                     'Страна: ' + str(local.get('region', '')),
                     'Оператор по справочнику: ' + str(local.get('carrier', '')),
                     'Часовой пояс: ' + (zones[0] if len(zones) == 1 else 'Однозначно не определён'),
                     'Оператор может отличаться после переноса номера. Геолокация не определяется.',
                     'Дата запроса: ' + data.get('queried_at', ''), '',
                     'Поисковый запрос: ' + data.get('search_query', ''), '']
            for source, rows in data['sources'].items():
                lines.append('— ' + source + ' —')
                if isinstance(rows, list):
                    if not rows:
                        lines.append('Публичных совпадений не найдено.')
                    for index, row in enumerate(rows, 1):
                        lines.extend([str(index) + '. ' + row.get('title', ''), row.get('url', ''),
                                      row.get('snippet', ''), row.get('verification', ''), ''])
                else:
                    lines.append(json.dumps(rows, ensure_ascii=False, indent=2))
                lines.append('')
            for source, error in data.get('errors', {}).items():
                lines.append(source + ': ' + str(error))
            lines.extend(['', 'Совпадение номера на странице не подтверждает личность или актуального владельца.'])
            self.phone_output.insert('end', '\n'.join(lines))
        else:
            self.phone_output.insert('end', json.dumps(data, ensure_ascii=False, indent=2))
        self.phone_output.configure(state='disabled')

    def _phone_local(self):
        if 'phone' in self.extra_busy:
            return
        try:
            self._phone_show({'Справочные данные': PhoneLookup.local(self.phone_number.get()),
                             'Примечание': 'Регион и часовые пояса относятся к плану нумерации. Оператор может отличаться после переноса номера.'})
            self.phone_status.configure(text='Локальная проверка завершена. Интернет не использовался.')
        except Exception as error:
            messagebox.showerror('Номер телефона', str(error))

    def _phone_online(self):
        if 'phone' in self.extra_busy:
            return
        if not self.phone_consent.get():
            messagebox.showinfo('Интернет-поиск', 'Отметьте разрешение на передачу номера выбранным сервисам.')
            return
        providers = {name: self.phone_keys[name].get().strip() for name in ('Numverify', 'SerpAPI', 'GitHub', 'Brave') if self.phone_enabled[name].get()}
        if not providers or any(not value for value in providers.values()):
            messagebox.showinfo('API', 'Выберите хотя бы один сервис поиска номера и заполните его ключ.')
            return
        number = self.phone_number.get()
        self.phone_status.configure(text='Запросы выбранным сервисам…')
        self._extra_job('phone', lambda emit: PhoneLookup.online(number, providers))

    def _phone_geocode(self):
        if 'phone' in self.extra_busy:
            return
        key, place = self.phone_keys['OpenCage'].get().strip(), self.phone_place.get().strip()
        if not self.phone_consent.get() or not self.phone_enabled['OpenCage'].get() or not key or not place:
            messagebox.showinfo('OpenCage', 'Отметьте OpenCage и разрешение на запрос, введите ключ и название места.')
            return
        self.phone_status.configure(text='Геокодирование введённого места…')
        def work(emit):
            return {'Запрос места': place, 'Результаты': PhoneLookup.geocode(place, key),
                    'Примечание': 'Это координаты найденного места, НЕ местоположение телефона. © OpenCage; данные OpenStreetMap contributors и других источников: https://opencagedata.com/credits'}
        self._extra_job('phone', work)

    def _phone_save(self):
        import json
        if self.phone_result is None:
            return
        path = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON', '*.json')])
        if path:
            try:
                Path(path).write_text(json.dumps(self.phone_result, ensure_ascii=False, indent=2), encoding='utf-8')
            except OSError as error:
                messagebox.showerror('Сохранение', str(error))


if __name__ == '__main__':
    app = ModernOSINTApp()
    app.mainloop()
