# analyzer.py — импорт, правила, контекст, фильтрация и автономный отчёт.
import hashlib
import html
import re
import unicodedata
from datetime import datetime
from pathlib import Path
from patterns import APP_NAME, RULES_VERSION, THREAT_PATTERNS, THREAT_LEVELS, KEYWORD_FORMS, IDIOM_PATTERNS, CONTEXT_RADIUS, CONTEXT_MINUTES, CONTEXT_CUES, INTENT_CAVEATS, MIXED_CHARACTERS, SPELLING_ALIASES, SEPARATED_WORDS, CONTEXT_ONLY_WORDS


class WhatsAppAnalyzer:
    # Поддержка квадратных скобок, разделителей даты . / -, секунд и AM/PM.
    HEADER = re.compile(
        r'^\[?(?P<date>\d{1,4}[./-]\d{1,2}[./-]\d{2,4}),?\s+'
        r'(?P<time>\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM)?)'
        r'(?:\]\s*|\s+[-–]\s*)(?P<body>.*)$', re.I)
    DATE_START = re.compile(r'^\[?\d{1,4}[./-]\d{1,2}[./-]\d{1,4}')

    def __init__(self):
        self.patterns = self._prepare_patterns()
        self.idioms = self._compile(IDIOM_PATTERNS)
        self.context_cues = {key: self._compile(value) for key, value in CONTEXT_CUES.items()}
        self.intent_caveats = self._compile(INTENT_CAVEATS)

    @staticmethod
    def _compile(expressions):
        return [re.compile(r'(?<!\w)(?:' + expression + r')(?!\w)', re.I)
                for expression in expressions]

    @staticmethod
    def normalize_for_search(text):
        chars, offsets = [], []
        for index, ch in enumerate(text):
            if ch in '\u200b\u200c\u200d\ufeff':
                continue
            for normalized in unicodedata.normalize('NFKC', ch).casefold():
                chars.append(normalized)
                offsets.append((index, index+1))
        normalized = ''.join(chars)
        # Подмены латиницей/цифрами исправляются только в смешанных кириллических словах.
        translated = list(normalized)
        for token in re.finditer(r'\w+', normalized):
            if re.search('[а-яё]', token.group()):
                for index in range(token.start(), token.end()):
                    translated[index] = MIXED_CHARACTERS.get(translated[index], translated[index])
        normalized = ''.join(translated)

        def replace_tokens(pattern, replacement):
            nonlocal normalized, offsets
            result, mapping, cursor = [], [], 0
            for match in pattern.finditer(normalized):
                result.append(normalized[cursor:match.start()])
                mapping.extend(offsets[cursor:match.start()])
                value = replacement(match)
                if value == match.group():
                    result.append(value)
                    mapping.extend(offsets[match.start():match.end()])
                else:
                    result.append(value)
                    span = (offsets[match.start()][0], offsets[match.end()-1][1])
                    mapping.extend([span]*len(value))
                cursor = match.end()
            result.append(normalized[cursor:])
            mapping.extend(offsets[cursor:])
            normalized, offsets = ''.join(result), mapping

        replace_tokens(re.compile(r'\w+'), lambda match: SPELLING_ALIASES.get(match.group(), match.group()))
        for word in sorted(SEPARATED_WORDS, key=len, reverse=True):
            expression = r'(?<!\w)' + r'[. _*\-]{0,3}'.join(map(re.escape, word)) + r'(?!\w)'
            replace_tokens(re.compile(expression), lambda match, word=word: word)
        return normalized, offsets

    @staticmethod
    def original_span(message, match):
        offsets = message['search_offsets']
        return offsets[match.start()][0], offsets[match.end()-1][1]

    def _prepare_patterns(self):
        output = []
        for category_index, category in enumerate(THREAT_PATTERNS, 1):
            for rule in category['rules']:
                output.append(dict(rule, category=category['category'], threat_level=rule['threat_level'],
                                   color=category['color'], kind='rule',
                                   primary=self._compile(rule['patterns']),
                                   required=self._compile(rule.get('context', [])),
                                   excluded=self._compile(rule.get('exclude', []))))
            # Длинные выражения имеют приоритет над вложенными отдельными словами.
            words = sorted(dict.fromkeys(word.casefold() for word in category.get('keywords', [])),
                           key=lambda word: (-len(word), word))
            seen_expressions = set()
            for index, word in enumerate(words, 1):
                expression = KEYWORD_FORMS.get(word, ''.join('[её]' if ch in 'её' else re.escape(ch) for ch in word))
                if expression in seen_expressions:
                    continue
                seen_expressions.add(expression)
                output.append(dict(id=f'KW{category_index:02d}-{index:03d}',
                    title='Словарное совпадение: ' + word, category=category['category'],
                    threat_level='Низкий', color=category['color'], kind='dictionary', keyword=word,
                    primary=self._compile([expression]), required=[], excluded=[]))
        return output

    @staticmethod
    def highest_level(names):
        # Порядок категорий угрозы, а не накопительная оценка.
        present = set(names)
        return next((level for level in reversed(THREAT_LEVELS)
                     if level['name'] in present), THREAT_LEVELS[0])

    @classmethod
    def threat_level(cls, findings):
        return cls.highest_level(finding['threat_level'] for finding in findings)

    @staticmethod
    def read_file(path):
        data = Path(path).read_bytes()
        if data.startswith((b'\xff\xfe', b'\xfe\xff')):
            candidates = ['utf-16']
        elif b'\x00' in data[:1000]:
            raise ValueError('Файл содержит нулевые байты. Нужен текстовый экспорт UTF-8 или UTF-16 с BOM.')
        else:
            candidates = ['utf-8-sig', 'cp1251']
        for encoding in candidates:
            try:
                text = data.decode(encoding)
                return text, encoding, hashlib.sha256(data).hexdigest()
            except UnicodeError:
                continue
        raise ValueError('Кодировка не распознана. Сохраните экспорт как UTF-8.')

    @staticmethod
    def _valid_datetime(date, time):
        parts = re.split(r'[./-]', date)
        if len(parts[0]) == 4:
            fmt = '%Y-%m-%d'
        else:
            fmt = '%d-%m-%Y' if len(parts[2]) == 4 else '%d-%m-%y'
        t = time.strip().upper()
        tfmt = '%I:%M' if re.search(r'(AM|PM)$', t) else '%H:%M'
        if t.count(':') == 2:
            tfmt += ':%S'
        if re.search(r'(AM|PM)$', t):
            tfmt += ' %p'
            t = re.sub(r'\s*(AM|PM)$', r' \1', t)
        return datetime.strptime('-'.join(parts) + ' ' + t, fmt + ' ' + tfmt)

    def analyze(self, text, filename='', encoding='текст', digest='', source_id='', demo=False):
        messages, issues = [], []
        system_count = continuation_count = blank_count = 0
        current = None
        lines = text.splitlines()
        for number, raw in enumerate(lines, 1):
            line = raw.lstrip('\ufeff\u200e\u200f').replace('\u202f', ' ').replace('\u00a0', ' ')
            match = self.HEADER.match(line)
            if match:
                current = None
                date, time, body = match.group('date', 'time', 'body')
                try:
                    timestamp = self._valid_datetime(date, time)
                except ValueError:
                    issues.append(dict(line=number, reason='Некорректная дата/время; порядок даты — день/месяц/год', text=raw))
                    continue
                if ': ' not in body:
                    system_count += 1
                    continue
                sender, body = body.split(': ', 1)
                if not sender.strip():
                    issues.append(dict(line=number, reason='Пустой отправитель', text=raw))
                    continue
                current = dict(date=date, time=time.strip(), sender=sender.strip(), text=body,
                               line=number, end_line=number, index=len(messages), timestamp=timestamp)
                messages.append(current)
            elif self.DATE_START.match(line):
                issues.append(dict(line=number, reason='Не распознан заголовок сообщения', text=raw))
                current = None
            elif not line.strip():
                blank_count += 1
                if current is not None:
                    current['text'] += '\n'
                    current['end_line'] = number
            elif current is not None:
                current['text'] += '\n' + raw
                current['end_line'] = number
                continuation_count += 1
            else:
                issues.append(dict(line=number, reason='Строка вне сообщения', text=raw))
        for message in messages:
            message['search_text'], message['search_offsets'] = self.normalize_for_search(message['text'])
        stats = {c['category']: dict(count=0, color=c['color']) for c in THREAT_PATTERNS}
        findings, sender_messages, sender_threat = [], {}, {}
        for msg in messages:
            sender = msg['sender']
            sender_messages[sender] = sender_messages.get(sender, 0) + 1
            sender_threat.setdefault(sender, 'Низкий')
            for finding in self.scan_message(msg, messages, filename, source_id):
                findings.append(finding)
                stats[finding['category']]['count'] += 1
                sender_threat[sender] = self.highest_level((sender_threat[sender], finding['threat_level']))['name']
        return dict(filename=filename, source_id=source_id, demo=demo, encoding=encoding, sha256=digest,
                    total_messages=len(messages), total_findings=len(findings),
                    findings=findings, messages=messages, stats=stats, threat_level=self.threat_level(findings),
                    contacts=sorted(sender_messages, key=str.casefold), sender_messages=sender_messages,
                    sender_threat=sender_threat, import_info=dict(lines=len(lines), issues=issues,
                    system=system_count, continuation=continuation_count, blank=blank_count))

    def scan_message(self, msg, messages, filename='', source_id=''):
        findings = []
        sender = msg['sender']
        covered_spans = {}
        idiom_spans = [(hit.start(), hit.end()) for regex in self.idioms for hit in regex.finditer(msg['search_text'])]
        neighborhood = self.neighborhood(messages, msg['index'])
        # Для намерения — только непрерывная цепочка предыдущих реплик автора.
        author_context = [msg]
        for previous in reversed(messages[max(0, msg['index']-CONTEXT_RADIUS):msg['index']]):
            if previous['sender'] != sender or abs((msg['timestamp']-previous['timestamp']).total_seconds()) > CONTEXT_MINUTES*60:
                break
            author_context.insert(0, previous)
        for rule in self.patterns:
            hits = [m for regex in rule['primary'] for m in regex.finditer(msg['search_text'])]
            hits = [hit for hit in hits if not any(hit.start() < end and hit.end() > start for start, end in idiom_spans)]
            if rule['kind'] == 'dictionary':
                previous = covered_spans.get(rule['category'], []) + idiom_spans
                hits = [hit for hit in hits if not any(
                    hit.start() < end and hit.end() > start for start, end in previous)]
            if not hits or any(regex.search(msg['search_text']) for regex in rule['excluded']):
                continue
            # Контекст текущего сообщения ограничен окрестностью совпадения.
            local_parts = [msg['search_text'][max(0, h.start()-160):h.end()+160] for h in hits]
            local_message = dict(msg, search_text=' '.join(local_parts))
            context_messages = ([dict(m, search_text=m['search_text'][-240:]) for m in author_context[:-1]] + [local_message]
                                if rule.get('context_scope') == 'same_author' else [local_message])
            context_hits = [(message, hit.group()) for message in context_messages
                            for regex in rule['required'] for hit in regex.finditer(message['search_text'])]
            context = [word for message, word in context_hits]
            evidence = {message['index'] for message, word in context_hits}
            local_level = rule['threat_level']
            caveat = rule.get('intent_rule', False) and any(
                regex.search(message['search_text']) for message in context_messages for regex in self.intent_caveats)
            if rule['kind'] == 'dictionary':
                cue_hits = [(message, hit.group()) for message in [local_message if m['index'] == msg['index'] else m for m in neighborhood]
                            for regex in self.context_cues.get(rule['category'], [])
                            for hit in regex.finditer(message['search_text'])]
                evidence.update(message['index'] for message, word in cue_hits)
            else:
                cue_hits = []
            if rule['kind'] == 'dictionary':
                cue_hits = [(message, word) for message, word in cue_hits
                            if word.casefold() not in {hit.group().casefold() for hit in hits}]
                # Бытовой контекст не должен становиться подтверждением сленга.
                cue_hits = [(message, word) for message, word in cue_hits
                            if not any(regex.search(message['search_text']) for regex in self.idioms)]
                if rule.get('keyword') in CONTEXT_ONLY_WORDS and not cue_hits:
                    continue
                evidence = {message['index'] for message, word in cue_hits}
            if rule['required'] and not context:
                continue
            spans = sorted(set(self.original_span(msg, hit) for hit in hits))
            words = list(dict.fromkeys(msg['text'][start:end] for start, end in spans))
            recognized = list(dict.fromkeys(hit.group() for hit in hits))
            review_status = 'Требует проверки контекста'
            reason = 'Найдено: ' + ', '.join(words)
            if [word.casefold() for word in words] != recognized:
                reason += '. Распознано написание: ' + ', '.join(recognized)
            if rule['kind'] == 'dictionary':
                reason += '. Словарный признак; возможны бытовое, профессиональное, сленговое или кодовое значения'
            reason += '. ' + review_status
            if caveat:
                local_level = 'Низкий'
                reason += '. Есть отрицание, пересказ, учебная или условная формулировка; намерение автора не установлено'
            if cue_hits:
                reason += '. В текущем фрагменте или ближайшем контексте также найдено: ' + ', '.join(dict.fromkeys(word for message, word in cue_hits))
                reason += '; слова другого участника не приписываются автору'
            if context:
                reason += '. Дополнительный признак в тексте: ' + ', '.join(dict.fromkeys(context))
            reason += '. Уровень угрозы: ' + local_level + '.'
            if evidence:
                reason += ' Контекст: строки ' + ', '.join(str(messages[i]['line']) for i in sorted(evidence)) + '.'
            findings.append(dict(date=msg['date'], time=msg['time'], sender=sender,
                                 word=', '.join(words), text=msg['text'], category=rule['category'],
                                 threat_level=local_level, color=rule['color'], rule_id=rule['id'],
                                 context_indices=sorted(evidence),
                                 rule_title=rule['title'], reason=reason, review_status=review_status,
                                 requires_context=True, kind=rule['kind'], message_index=msg['index'],
                                 line=msg['line'], spans=spans,
                                 file=filename, source_id=source_id))
            covered_spans.setdefault(rule['category'], []).extend((hit.start(), hit.end()) for hit in hits)
        return findings

    @staticmethod
    def filter_findings(findings, query='', category=None, sender=None, filename=None):
        query = query.strip().casefold()
        return [item for item in findings
                if (category is None or item['category'] == category)
                and (sender is None or item['sender'] == sender)
                and (filename is None or item['file'] == filename)
                and (not query or query in ' '.join(str(item.get(k, '')) for k in
                     ('text', 'word', 'sender', 'category', 'file', 'date', 'time', 'rule_id', 'review_status')).casefold())]

    @staticmethod
    def neighborhood(messages, index, radius=CONTEXT_RADIUS):
        center = messages[index]
        return [message for message in messages[max(0, index-radius):index+radius+1]
                if abs((message['timestamp']-center['timestamp']).total_seconds()) <= CONTEXT_MINUTES*60]

    @classmethod
    def context(cls, result, finding, radius=CONTEXT_RADIUS):
        return cls.neighborhood(result['messages'], finding['message_index'], radius)

    @staticmethod
    def demo_chats():
        return [
            ('Демо — проверка сообщений.txt',
             '12.09.2026, 09:00 - Демо Анна: Встретимся у магазина, куплю сахар и муку.\n'
             '12.09.2026, 09:01 - Демо Борис: Хорошо. План занятия отправлю вечером.\n'
             '12.09.2026, 09:02 - Демо Анна: Пришли код из СМС для проверки.\n'
             '12.09.2026, 09:03 - Демо Борис: Это похоже на мошенничество.\n'
             'Проверю отправителя через официальный номер.\n'
             '12.09.2026, 09:04 - Демо Анна: Никому не сообщайте код из СМС.\n'),
            ('Демо — проверка импорта.txt',
             'Синтетический пример: все участники и сообщения вымышлены.\n'
             '[12.09.2026, 10:00:00] Демо Борис: Обсудим учебный пример.\n'
             '[12.09.2026, 10:01:00] Демо Вера: В обращении описан взлом аккаунта.\n'
             '[12.09.2026, 10:02:00] Демо Борис: Добавим сообщение в отчёт с контекстом.\n'
             '32.09.2026, 10:03 - Демо Вера: Пример некорректной даты.\n')]

    def write_report(self, path, results, findings, note='', scope='Все совпадения', rejected_files=()):
        e = lambda value: html.escape(str(value), quote=True)
        level = self.threat_level([f for r in results for f in r['findings']])
        demo = any(r['demo'] for r in results)
        parts = ['<!doctype html><html lang="ru"><meta charset="utf-8">',
                 '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">',
                 '<title>Отчёт — Whatsapp_Osint_analyzer</title><style>',
                 'body{font:15px Arial;color:#202b3c;background:#edf0f4;margin:0}'
                 'main{max-width:1050px;margin:28px auto;background:white;padding:36px;border:1px solid #ccd3dc}'
                 'h1,h2{color:#203c60}article{border:1px solid #cbd3df;padding:18px;margin:18px 0;break-inside:avoid}'
                 'pre{white-space:pre-wrap;overflow-wrap:anywhere;font:inherit}table{border-collapse:collapse;width:100%}'
                 'td,th{border:1px solid #ccd3dc;padding:8px;text-align:left;overflow-wrap:anywhere}'
                 '.hit{background:#fff1c5;padding:8px}.muted{color:#546478}'
                 '@media print{body{background:white}main{margin:0;border:0;padding:0}}',
                 '</style><main><h1>Whatsapp_Osint_analyzer</h1><h2>Отчёт по результатам анализа</h2>',
                 '<p><b>ДЕМОНСТРАЦИОННЫЕ ДАННЫЕ</b></p>' if demo else '',
                 f'<p>Сформирован: {e(datetime.now().strftime("%d.%m.%Y %H:%M"))}. Правила: {e(RULES_VERSION)}.</p>',
                 f'<p>Файлов: {len(results)} · Сообщений: {sum(r["total_messages"] for r in results)} · '
                 f'Совпадений всего: {sum(r["total_findings"] for r in results)} · Уровень угрозы: {e(level["name"])}.</p>',
                 f'<p>Состав отчёта: {e(scope)}. Включено совпадений: {len(findings)}; '
                 f'уровень угрозы выборки: {e(self.threat_level(findings)["name"])}.</p>',
                 '<p class="muted">Уровень угрозы определяется характером найденных выражений. '
                 'Совпадение требует проверки контекста и не устанавливает причастность участника.</p>',
                 f'<h2>Комментарий аналитика</h2><pre>{e(note or "Не указан")}</pre>',
                 '<h2>Качество импорта</h2><p>Порядок числовых дат: день/месяц/год; также год-месяц-день. '
                 'Строки без заголовка после сообщения считаются его продолжением.</p><table>'
                 '<tr><th>Файл</th><th>Сообщения</th><th>Кодировка</th><th>Проблемные строки</th></tr>']
        by_id = {r['source_id']: r for r in results}
        for r in results:
            parts.append(f'<tr><td>{e(r["filename"])}</td><td>{r["total_messages"]}</td>'
                         f'<td>{e(r["encoding"])}</td><td>{len(r["import_info"]["issues"])}</td></tr>')
        parts.append('</table><h2>Совпадения и контекст</h2>')
        for f in findings:
            parts.append(f'<article><h3>{e(f["rule_id"])} · {e(f["rule_title"])}</h3>'
                         f'<p>{e(f["file"])} · строка {f["line"]} · {e(f["category"])}</p>'
                         f'<p><b>{e(f["review_status"])}</b></p><p>{e(f["reason"])}</p>')
            for msg in self.context(by_id[f['source_id']], f):
                css = ' class="hit"' if msg['index'] == f['message_index'] else ''
                parts.append(f'<pre{css}>{e(msg["date"])} {e(msg["time"])} | {e(msg["sender"])}\n{e(msg["text"])}</pre>')
            parts.append('</article>')
        parts.append('<h2>Примечания к импорту</h2>')
        for r in results:
            parts.append(f'<h3>{e(r["filename"])}</h3>')
            for issue in r['import_info']['issues']:
                parts.append(f'<pre>Строка {issue["line"]}: {e(issue["reason"])}\n{e(issue["text"])}</pre>')
        if rejected_files:
            parts.append('<h2>Не загруженные файлы</h2>')
            for name, reason in rejected_files:
                parts.append(f'<p>{e(name)}: {e(reason)}</p>')
        parts.append('</main></html>')
        Path(path).write_text('\n'.join(parts), encoding='utf-8')


# Дополнительные источники. Импорты тяжёлых библиотек отложены до использования.
class DocumentSearch:
    @staticmethod
    def extract(paths):
        from pathlib import Path
        import zipfile
        import xml.etree.ElementTree as ET
        blocks, issues = [], []
        for filename in dict.fromkeys(paths):
            path = Path(filename).resolve()
            try:
                suffix = path.suffix.lower()
                parts = []
                if suffix == '.txt':
                    text, _, _ = WhatsAppAnalyzer.read_file(path)
                    parts = [(f'Строка {i}', line) for i, line in enumerate(text.splitlines(), 1) if line.strip()]
                elif suffix == '.docx':
                    with zipfile.ZipFile(path) as archive:
                        root = ET.fromstring(archive.read('word/document.xml'))
                    ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
                    for i, paragraph in enumerate(root.findall('.//w:p', ns), 1):
                        value = ''.join(node.text or '' for node in paragraph.findall('.//w:t', ns))
                        if value.strip():
                            parts.append((f'Абзац {i}', value))
                elif suffix == '.pdf':
                    import pymupdf
                    with pymupdf.open(path) as doc:
                        if doc.needs_pass:
                            raise ValueError('PDF защищён паролем')
                        empty = 0
                        for i, page in enumerate(doc, 1):
                            value = page.get_text('text', sort=True)
                            if value.strip():
                                parts.append((f'Страница {i}', value))
                            else:
                                empty += 1
                        if empty:
                            issues.append(f'{path.name}: {empty} страниц без текстового слоя; OCR не выполнялся.')
                else:
                    raise ValueError('Поддерживаются TXT, DOCX и PDF')
                blocks.extend({'source': str(path), 'location': location, 'text': value} for location, value in parts)
                if not parts:
                    issues.append(f'{path.name}: извлекаемый текст не найден.')
            except Exception as error:
                issues.append(f'{path.name}: {error}')
        return blocks, issues

    @staticmethod
    def extract_and_analyze(paths, emit):
        emit('status', 'Извлечение текста…')
        blocks, issues = DocumentSearch.extract(paths)
        engine = WhatsAppAnalyzer()
        findings = []
        for index, block in enumerate(blocks):
            # Separate sentences/lines so context elsewhere on a page is not attributed to this phrase.
            # Dots within letter-separated obfuscation stay inside the fragment.
            fragments = re.split(r'(?<=[.!?])\s+(?=[А-ЯA-Z])|\n+', block['text'])
            for fragment in fragments:
                if not fragment.strip():
                    continue
                normalized, offsets = engine.normalize_for_search(fragment)
                msg = dict(text=fragment, search_text=normalized, search_offsets=offsets,
                           sender='Текст документа', index=0, timestamp=datetime(2000, 1, 1),
                           date='', time='', line=index+1)
                for finding in engine.scan_message(msg, [msg], Path(block['source']).name, block['source']):
                    findings.append(dict(block, excerpt=fragment.strip(),
                                         category=finding['category'], threat_level=finding['threat_level'],
                                         word=finding['word'], reason=finding['reason'],
                                         rule_id=finding['rule_id'], review_status=finding['review_status']))
            if index % 25 == 0:
                emit('status', f'Автоанализ: {index+1} из {len(blocks)} блоков…')
        return blocks, findings, issues

    @staticmethod
    def search(blocks, query):
        import re
        query = query.strip()
        if not query:
            return []
        pattern = re.compile(re.escape(query), re.IGNORECASE)
        hits = []
        for block in blocks:
            match = pattern.search(block['text'])
            if match:
                start, end = max(0, match.start() - 90), min(len(block['text']), match.end() + 180)
                hits.append(dict(block, excerpt=block['text'][start:end].replace('\n', ' ')))
        return hits


def write_table_csv(path, rows, fields):
    import csv
    def safe(value):
        value = str(value if value is not None else '')
        return "'" + value if value.lstrip().startswith(('=', '+', '-', '@')) else value
    with open(path, 'w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.writer(stream, delimiter=';')
        writer.writerow([title for key, title in fields])
        for row in rows:
            writer.writerow([safe(row.get(key, '')) for key, title in fields])


class LocalTranscriber:
    REQUIRED_FILES = ('model.bin', 'config.json', 'tokenizer.json')

    @classmethod
    def model_complete(cls, folder):
        return all((Path(folder) / name).is_file() for name in cls.REQUIRED_FILES)

    @classmethod
    def default_model_path(cls):
        import sys
        base = Path(sys.executable).resolve().parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parent
        candidates = [base / 'models' / 'small']
        # Стандартная сборка лежит в dist, а загруженная модель — в папке проекта.
        if getattr(sys, 'frozen', False):
            candidates.append(base.parent / 'models' / 'small')
        return next((folder for folder in candidates if cls.model_complete(folder)), candidates[0])

    @staticmethod
    def run(audio_path, model_path, language, cancel, emit):
        import os
        from pathlib import Path
        # Запрещаем загрузки даже при неполной локальной модели.
        os.environ['HF_HUB_OFFLINE'] = '1'
        os.environ['HF_HUB_DISABLE_TELEMETRY'] = '1'
        folder = Path(model_path)
        missing = [name for name in LocalTranscriber.REQUIRED_FILES if not (folder / name).is_file()]
        if missing:
            raise ValueError(
                f'В выбранной папке модели отсутствуют: {", ".join(missing)}.\n\n'
                f'Проверяемая папка: {folder}\n\n'
                'Нажмите «Папка модели» и выберите models\\small в папке проекта. '
                'Если модель ещё не скачана, запустите DOWNLOAD_MODEL.bat. '
                'При переносе EXE на другой компьютер скопируйте рядом с ним папку models.')
        from faster_whisper import WhisperModel
        emit('status', 'Загрузка модели в память…')
        model = WhisperModel(str(folder.resolve()), device='cpu', compute_type='int8', local_files_only=True)
        try:
            if cancel.is_set():
                return
            segments, info = model.transcribe(str(audio_path), language=language, beam_size=5, vad_filter=False)
            emit('status', f'Распознавание: язык {info.language}. Остановка применяется между фрагментами.')
            for segment in segments:
                if cancel.is_set():
                    break
                emit('segment', {'start': segment.start, 'end': segment.end, 'text': segment.text.strip()})
        finally:
            del model

    @staticmethod
    def stamp(seconds, srt=False):
        millis = max(0, round(float(seconds) * 1000))
        hours, remainder = divmod(millis, 3600000)
        minutes, remainder = divmod(remainder, 60000)
        seconds, millis = divmod(remainder, 1000)
        return f'{hours:02}:{minutes:02}:{seconds:02}' + (f',{millis:03}' if srt else '')

    @staticmethod
    def save(path, segments, source, partial=False):
        from pathlib import Path
        with open(path, 'w', encoding='utf-8') as stream:
            if Path(path).suffix.lower() == '.srt':
                for i, item in enumerate(segments, 1):
                    stream.write(f"{i}\n{LocalTranscriber.stamp(item['start'], True)} --> {LocalTranscriber.stamp(item['end'], True)}\n{item['text']}\n\n")
            else:
                stream.write(f'Источник: {source}\nАвтоматическая расшифровка — требует сверки с записью.\n')
                if partial:
                    stream.write('НЕПОЛНАЯ РАСШИФРОВКА: обработка остановлена или завершилась ошибкой.\n')
                for item in segments:
                    stream.write(f"[{LocalTranscriber.stamp(item['start'])} — {LocalTranscriber.stamp(item['end'])}] {item['text']}\n")


class EventData:
    @staticmethod
    def validate(item):
        import math
        from datetime import datetime
        title = str(item.get('title', '')).strip()
        if not title:
            raise ValueError('Укажите название события')
        lat, lon = float(str(item['lat']).replace(',', '.')), float(str(item['lon']).replace(',', '.'))
        if not math.isfinite(lat) or not math.isfinite(lon) or not (-85.05112878 <= lat <= 85.05112878 and -180 <= lon <= 180):
            raise ValueError('Широта: от −85.05112878 до 85.05112878; долгота: от −180 до 180 (проекция Меркатора).')
        date = str(item.get('date', '')).strip()
        if date:
            date = datetime.fromisoformat(date).isoformat(sep=' ', timespec='minutes')
        return {'title': title, 'date': date, 'lat': lat, 'lon': lon,
                'source': str(item.get('source', '')), 'description': str(item.get('description', ''))}

    @staticmethod
    def load(path):
        import json
        with open(path, encoding='utf-8-sig') as stream:
            payload = json.load(stream)
        rows = payload.get('events') if isinstance(payload, dict) else payload
        if not isinstance(rows, list):
            raise ValueError('Ожидается JSON-массив событий или объект с полем events')
        # Всё проверяется до замены текущего набора.
        return [EventData.validate(row) for row in rows]

    @staticmethod
    def save(path, events):
        import json
        from pathlib import Path
        target = Path(path)
        temporary = target.with_name(target.name + '.tmp')
        with open(temporary, 'w', encoding='utf-8') as stream:
            json.dump({'events': events}, stream, ensure_ascii=False, indent=2)
        temporary.replace(target)

    @staticmethod
    def project(lat, lon, zoom):
        import math
        size = 256 * 2 ** zoom
        latitude = math.radians(max(-85.05112878, min(85.05112878, lat)))
        return (lon + 180) / 360 * size, (1 - math.asinh(math.tan(latitude)) / math.pi) / 2 * size

    @staticmethod
    def unproject(x, y, zoom):
        import math
        size = 256 * 2 ** zoom
        return math.degrees(math.atan(math.sinh(math.pi * (1 - 2 * max(0, min(size, y)) / size)))), (x / size * 360 - 180 + 180) % 360 - 180


class OfflineTiles:
    def __init__(self, path):
        import sqlite3
        from pathlib import Path
        self.connection = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)
        try:
            self.metadata = dict(self.connection.execute('SELECT name, value FROM metadata'))
            if self.metadata.get('format', '').lower() not in ('png', 'jpg', 'jpeg', 'webp'):
                raise ValueError('Нужен растровый MBTiles (PNG/JPEG/WebP). Векторный PBF не поддерживается.')
            low, high = self.connection.execute('SELECT MIN(zoom_level), MAX(zoom_level) FROM tiles').fetchone()
            if low is None:
                raise ValueError('В MBTiles нет тайлов')
            self.minimum, self.maximum = max(0, int(low)), min(22, int(high))
            if self.minimum > self.maximum:
                raise ValueError('Недопустимые уровни масштаба')
        except Exception:
            self.connection.close()
            raise

    def tile(self, zoom, x, y):
        row = self.connection.execute('SELECT tile_data FROM tiles WHERE zoom_level=? AND tile_column=? AND tile_row=? LIMIT 1',
                                      (zoom, x % (2 ** zoom), 2 ** zoom - 1 - y)).fetchone()
        return row[0] if row else None

    def close(self):
        self.connection.close()


class PhoneLookup:
    @staticmethod
    def local(number):
        import phonenumbers
        from phonenumbers import geocoder, carrier, timezone
        raw = number.strip()
        if not raw.startswith('+'):
            raise ValueError('Введите номер в международном формате, начиная с + и кода страны.')
        parsed = phonenumbers.parse(raw, None)
        if not phonenumbers.is_possible_number(parsed):
            raise ValueError('Невозможная длина или структура номера.')
        return {'number': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
                'valid': phonenumbers.is_valid_number(parsed),
                'country': phonenumbers.region_code_for_number(parsed) or 'Не определена',
                'region': geocoder.description_for_number(parsed, 'ru') or 'Не определён',
                'carrier': carrier.name_for_number(parsed, 'ru') or 'Не определён',
                'timezones': list(timezone.time_zones_for_number(parsed))}

    @staticmethod
    def request(endpoint, params, token=None, api_key=None):
        import json
        import urllib.request
        import urllib.parse
        import urllib.error
        headers = {'User-Agent': 'Whatsapp-Osint-Analyzer', 'Accept': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        if api_key:
            headers['X-Subscription-Token'] = api_key
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                return None
        request = urllib.request.Request(endpoint + '?' + urllib.parse.urlencode(params), headers=headers)
        try:
            with urllib.request.build_opener(NoRedirect()).open(request, timeout=25) as response:
                payload = response.read(4 * 1024 * 1024 + 1)
                if len(payload) > 4 * 1024 * 1024:
                    raise ValueError('Ответ сервиса слишком велик.')
            return json.loads(payload)
        except urllib.error.HTTPError as error:
            raise ValueError(f'HTTP {error.code}: проверьте ключ, доступ к API и лимит запросов.') from None
        except urllib.error.URLError as error:
            import ssl
            import socket
            if isinstance(error.reason, ssl.SSLCertVerificationError):
                message = 'Ошибка проверки сертификата. Проверьте hosts, прокси и сертификаты сети.'
            elif isinstance(error.reason, (TimeoutError, socket.timeout)):
                message = 'Тайм-аут соединения (25 секунд). Повторите запрос позднее.'
            elif isinstance(error.reason, socket.gaierror):
                message = 'DNS не смог определить адрес сервиса.'
            else:
                message = 'Не удалось установить защищённое соединение. Проверьте сеть и прокси.'
            raise ValueError(message) from None
        except TimeoutError:
            raise ValueError('Тайм-аут ответа (25 секунд). Повторите запрос позднее.') from None
        except OSError:
            raise ValueError('Соединение прервано при получении ответа.') from None

    @staticmethod
    def search_query(number):
        import phonenumbers
        parsed = phonenumbers.parse(number, None)
        variants = [number, number.lstrip('+'),
                    phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                    phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)]
        if parsed.country_code == 7:
            variants.append('8' + str(parsed.national_number))
        return ' OR '.join('"' + value + '"' for value in dict.fromkeys(variants))

    @staticmethod
    def search_rows(rows, url_field):
        import html
        from urllib.parse import urlsplit
        results, seen = [], set()
        for row in rows:
            url = str(row.get(url_field) or '')
            if urlsplit(url).scheme not in ('http', 'https') or url in seen:
                continue
            seen.add(url)
            snippet = html.unescape(re.sub(r'<[^>]*>', '', str(row.get('snippet') or row.get('description') or '')))
            results.append({'title': html.unescape(str(row.get('title') or 'Без названия')),
                            'url': url, 'snippet': snippet,
                            'verification': 'Поисковое совпадение. Проверьте номер и контекст на исходной странице.'})
        return results

    @classmethod
    def online(cls, number, providers):
        local = cls.local(number)
        number = local['number']
        result = {'local': local, 'sources': {}, 'errors': {}, 'queried_at': datetime.now().astimezone().isoformat()}
        result['search_query'] = cls.search_query(number)
        for provider, key in providers.items():
            try:
                if provider == 'Numverify':
                    data = cls.request('https://apilayer.net/api/validate', {'access_key': key, 'number': number})
                    if data.get('success') is False or data.get('error'):
                        raise ValueError('Сервис отклонил запрос: проверьте тариф, поддержку HTTPS, ключ и квоту.')
                    result['sources'][provider] = {name: data.get(name) for name in ('valid', 'international_format', 'country_name', 'location', 'carrier', 'line_type')}
                elif provider == 'SerpAPI':
                    data = cls.request('https://serpapi.com/search.json', {'engine': 'google', 'q': result['search_query'], 'api_key': key, 'num': 10, 'hl': 'ru', 'gl': 'kz'})
                    if data.get('error') and data.get('search_metadata', {}).get('status') != 'Success':
                        detail = str(data['error']).replace(key, '[ключ скрыт]')
                        detail = re.sub(r'https?://\S+', '[адрес скрыт]', detail)
                        raise ValueError('SerpAPI: ' + detail[:350])
                    result['sources'][provider] = cls.search_rows(data.get('organic_results', [])[:10], 'link')
                elif provider == 'Brave':
                    data = cls.request('https://api.search.brave.com/res/v1/web/search',
                                       {'q': result['search_query'], 'count': 10, 'search_lang': 'ru'}, api_key=key)
                    if data.get('error'):
                        raise ValueError('Brave отклонил запрос. Проверьте доступ к Web Search API и квоту.')
                    result['sources'][provider] = cls.search_rows(data.get('web', {}).get('results', [])[:10], 'url')
                elif provider == 'GitHub':
                    data = cls.request('https://api.github.com/search/code', {'q': '"'+number+'" is:public', 'per_page': 10}, token=key)
                    # Не загружаем содержимое файлов и не выводим секреты из кода.
                    result['sources'][provider] = [{'title': row.get('name', ''), 'url': row.get('html_url', '')} for row in data.get('items', [])[:10] if not row.get('repository', {}).get('private', False)]
            except Exception as error:
                result['errors'][provider] = str(error)
        return result

    @classmethod
    def geocode(cls, place, key):
        if not place.strip():
            raise ValueError('Введите название места или адрес, а не телефонный номер.')
        data = cls.request('https://api.opencagedata.com/geocode/v1/json', {'q': place.strip(), 'key': key, 'limit': 5, 'language': 'ru', 'no_record': 1})
        if data.get('status', {}).get('code') != 200:
            raise ValueError('OpenCage отклонил запрос. Проверьте ключ и квоту.')
        return [{'place': row.get('formatted', ''), 'coordinates': row.get('geometry', {}),
                 'timezone': row.get('annotations', {}).get('timezone', {}).get('name', ''),
                 'confidence': row.get('confidence')} for row in data.get('results', [])]
