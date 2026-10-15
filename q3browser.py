#!/usr/bin/env python3
"""
Q3 Server Browser v1.0 – Quake 3 Arena Server Browser mit RCON
"""

__version__ = "1.0.0"

import sys
import os
import re
import socket
import time
import subprocess
from dataclasses import dataclass, field
from typing import Any, Optional

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTableView, QHeaderView, QPushButton, QLineEdit, QTextEdit,
    QTabWidget, QSplitter, QStatusBar, QToolBar, QMenu, QMenuBar,
    QDialog, QFormLayout, QDialogButtonBox, QLabel,
    QSpinBox, QMessageBox, QFileDialog, QCheckBox,
    QProgressBar, QToolButton, QAbstractItemView,
    QStyle, QStyledItemDelegate
)
from PyQt6.QtCore import (
    Qt, QAbstractTableModel, QModelIndex, QThread,
    QObject, pyqtSignal, pyqtSlot,
    QTimer, QSettings, QSortFilterProxyModel, QSize
)
from PyQt6.QtGui import (
    QAction, QColor, QBrush, QFont, QKeySequence, QIcon,
    QPainter, QPalette, QTextCursor
)

# ── Konfiguration ────────────────────────────────────────────

MASTER_HOST = "master.ioquake3.org"
MASTER_PORT = 27950
PROTOCOL = 68
QUERY_TIMEOUT = 3
# Der Master schickt die Liste in mehreren UDP-Paketen (~1400 B Stück).
# Kurzes Lese-Timeout: sobald nichts mehr kommt, ist die Liste komplett.
MASTER_READ_TIMEOUT = 1.5
MASTER_RETRY_DELAY = 0.6
MASTER_GOT_REPLY = b"getserversResponse"
# Zeitfenster, um die Folgepakete einer langen RCON-Antwort einzufangen
RCON_TAIL_TIMEOUT = 0.5
MAX_CONCURRENT = 64
SCAN_ABORT_TIMEOUT_MS = 5000
APP_NAME = "Q3 Server Browser"
ORG_NAME = "q3browser"
SETTINGS_FILE = os.path.join(os.path.expanduser("~"), ".config", "q3browser.ini")

GAMETYPE_NAMES = {
    0: "FFA", 1: "Duel", 2: "Single", 3: "TDM", 4: "CTF",
}

# ── UDP / Protokoll ──────────────────────────────────────────

def make_ocp(cmd: bytes) -> bytes:
    return b"\xff\xff\xff\xff" + cmd

Q3_COLORS = {
    "0": QColor("#000000"), "1": QColor("#ff0000"),
    "2": QColor("#00ff00"), "3": QColor("#ffff00"),
    "4": QColor("#0000ff"), "5": QColor("#00ffff"),
    "6": QColor("#ff00ff"), "7": QColor("#ffffff"),
    "8": QColor("#ff8000"), "9": QColor("#808080"),
}

def parse_q3_colored(text: str) -> list[tuple[str, Optional[QColor]]]:
    segments: list[tuple[str, Optional[QColor]]] = []
    cur: Optional[QColor] = None
    i = 0
    while i < len(text):
        if text[i] == "^" and i + 1 < len(text) and text[i + 1] in Q3_COLORS:
            cur = Q3_COLORS[text[i + 1]]
            i += 2
            continue
        start = i
        while i < len(text) and not (text[i] == "^" and i + 1 < len(text)
                                      and text[i + 1] in Q3_COLORS):
            i += 1
        seg = text[start:i]
        if seg:
            segments.append((seg, cur))
    return segments

# Manche Server benutzen statt ^N auch echte Steuerzeichen als Farbcode,
# z.B. \x07 (BEL) oder \x1d-\x1f. Die wuerden als Muell in der Tabelle stehen.
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
# Wie _CTRL_RE, aber \t \n \r bleiben erhalten – fuer mehrzeilige RCON-Ausgabe
_CTRL_KEEP_NL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_COLOR_RE = re.compile(r"\^[0-9]")

def clean_control(text: str) -> str:
    """Steuerzeichen entfernen, ^N-Farbcodes aber BEIBEHALTEN.

    Wird fuer Spielernamen gebraucht, weil der QColoredTextDelegate die
    ^N-Codes noch zum Einfaerben braucht. Zeilenumbrueche werden hier
    absichtlich zu Leerzeichen – Namen sind einzeilig.
    """
    if not text:
        return ""
    return _CTRL_RE.sub(" ", text).strip()

def clean_output(text: str) -> str:
    """Fuer die RCON-Anzeige: ^N-Farbcodes und Steuerzeichen entfernen,
    aber Zeilenumbrueche und Tabs BEHALTEN – 'status' ist ein Textblock
    mit vielen Zeilen, der darf nicht in eine einzige Zeile zusammenfallen.
    """
    if not text:
        return ""
    return _CTRL_KEEP_NL_RE.sub(" ", _COLOR_RE.sub("", text)).strip()

def strip_colors(text: str) -> str:
    """Q3-Farbcodes ^0–^9 UND Steuerzeichen entfernen (fuer Hostnamen)."""
    if not text:
        return ""
    return clean_control(_COLOR_RE.sub("", text))

def _recv_master_list(sock: socket.socket) -> list[tuple[str, int]]:
    """Alle Datagramme eines Master-Antwort-Stoßes einsammeln."""
    servers: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    while True:
        try:
            data, _ = sock.recvfrom(65535)
        except (socket.timeout, OSError):
            # Master hat nichts mehr geschickt → Liste ist vollständig
            break

        idx = data.find(MASTER_GOT_REPLY)
        if idx == -1:
            continue
        pos = idx + len(MASTER_GOT_REPLY)

        while pos < len(data):
            if data[pos:pos + 1] != b"\\":
                break
            pos += 1
            if data[pos:pos + 3] == b"EOT":
                break
            if pos + 6 > len(data):
                break
            entry = (".".join(str(b) for b in data[pos:pos + 4]),
                     (data[pos + 4] << 8) | data[pos + 5])
            if entry not in seen:           # Duplikate über Paketgrenzen
                seen.add(entry)
                servers.append(entry)
            pos += 6
    return servers

def query_master(host: str = MASTER_HOST, port: int = MASTER_PORT,
                 timeout: int = 5, retries: int = 1) -> list[tuple[str, int]]:
    """Master-Server abfragen → Liste von (ip, port)

    Achtung: Der Master antwortet mit MEHREREN Datagrammen (je ~1400 Bytes,
    also ca. 196 Server pro Paket). Nur das erste Paket zu lesen liefert
    konstant 196 Server. Deshalb hier eine Lese-Schleife bis zum Timeout.
    Das letzte Paket endet mit '\\EOT' und ist auf 4 Bytes aufgefüllt.

    Bei schnellen Burst-Anfragen drosselt master.ioquake3.org sporadisch und
    antwortet gar nicht → daher 'retries'-mal erneut versuchen.
    """
    req = make_ocp(f"getservers {PROTOCOL} empty empty\n".encode())
    for attempt in range(retries + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(MASTER_READ_TIMEOUT)
        try:
            sock.sendto(req, (host, port))
            servers = _recv_master_list(sock)
        except OSError:
            servers = []
        finally:
            sock.close()
        if servers:
            return servers
        if attempt < retries:
            time.sleep(MASTER_RETRY_DELAY)
    return []

def query_getstatus(host: str, port: int,
                    timeout: int = QUERY_TIMEOUT) -> Optional[dict]:
    """getstatus → {info, players, ping} oder None"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    t0 = time.monotonic()
    req = make_ocp(b"getstatus\n")
    try:
        sock.sendto(req, (host, port))
        data, _ = sock.recvfrom(65535)
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()
    rtt = int((time.monotonic() - t0) * 1000)

    hdr = b"statusResponse\n"
    idx = data.find(hdr)
    if idx == -1:
        return None
    rest = data[idx + len(hdr):]

    parts = rest.split(b"\n", 1)
    header_part = parts[0]
    player_part = parts[1] if len(parts) > 1 else b""

    info = _parse_kv(header_part)
    players = _parse_players(player_part)
    info["ping"] = rtt
    return {"info": info, "players": players}

def _parse_kv(data: bytes) -> dict[str, str]:
    d: dict[str, str] = {}
    if not data or data[0:1] != b"\\":
        return d
    raw = data[1:].decode("latin-1", errors="replace")
    for i, token in enumerate(raw.split("\\")):
        if i % 2 == 0:
            key = token.strip()
        else:
            d[key] = token.strip()
    return d

def _int(val: Any, default: int = 0) -> int:
    """int() mit Fallback – verhindert, dass ein kaputter Serverwert
    den ganzen Server-Eintrag verwirft."""
    try:
        return int(str(val).strip())
    except (TypeError, ValueError):
        return default

def _parse_players(data: bytes) -> list[dict[str, Any]]:
    """Spielerzeilen parsen. Es existieren zwei Formate:

    modern:    0 33 "name"           (u.a. aktuelle ioquake3/CPMA-Server)
    klassisch: 0 33 0\\name\\          (Quake III 1.32c)
    """
    players: list[dict[str, Any]] = []
    for raw in data.split(b"\n"):
        line = raw.strip()
        if not line or line.lower().startswith(b"score ping"):
            continue                      # Kopfzeile "score ping ..."

        name: Optional[str] = None
        if b'"' in line:
            # modern: alles zwischen erster und letzter Anführungszeichen
            head, _, tail = line.partition(b'"')
            fp = head.split()
            name = (tail.rsplit(b'"', 1)[0] if tail.endswith(b'"') else tail)
        else:
            # klassisch: 0 33 0\name\
            head, sep, tail = line.partition(b"\\")
            if not sep:
                continue
            fp = head.split()
            name = tail[:-1] if tail.endswith(b"\\") else tail

        if len(fp) < 2:
            continue
        try:
            score = int(fp[0])
            ping = int(fp[1])
        except ValueError:
            continue
        players.append({"score": score, "ping": ping,
                        "name": clean_control(
                            name.decode("latin-1", errors="replace"))})
    return players

def rcon_send(host: str, port: int, password: str, command: str,
              timeout: int = 3) -> str:
    """RCON an Server senden, Antwort als String.

    Lange Antworten kommen in MEHREREN Paketen: der Server spult seinen
    Redirect-Puffer alle SV_OUTPUTBUF_LENGTH (= 1024 - 16) Bytes als eigenes
    'print\\n'-Paket ab. Nur ein Paket zu lesen schneidet z.B. 'status' auf
    einem vollen Server mitten in der Spielerliste ab – ohne Fehlermeldung.
    Deshalb: weiter lesen, solange noch Pakete kommen. Der Präfix muss pro
    Paket abgeschnitten werden, sonst stünde ab Paket 2 ein 'print' im Text.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    payload = f"rcon {password} {command}\n"
    chunks: list[bytes] = []
    try:
        sock.sendto(make_ocp(payload.encode()), (host, port))
        first = True
        while True:
            try:
                data, _ = sock.recvfrom(65535)
            except (socket.timeout, OSError):
                if first:
                    return "(Zeitüberschreitung / kein Response)"
                break                       # erste Antwort war da, Rest leer
            first = False
            # Folgepakete kommen unmittelbar hintereinander -> kurz warten
            sock.settimeout(RCON_TAIL_TIMEOUT)
            for prefix in (b"\xff\xff\xff\xffprint\n", b"\xff\xff\xff\xff"):
                if data.startswith(prefix):
                    data = data[len(prefix):]
                    break
            chunks.append(data)
    except OSError:
        return "(Zeitüberschreitung / kein Response)"
    finally:
        sock.close()

    return b"".join(chunks).decode("latin-1", errors="replace").strip()

def gametype_name(val: str) -> str:
    try:
        return GAMETYPE_NAMES.get(int(val), f"?{val}")
    except ValueError:
        return val or "?"

# ── Dataclass ─────────────────────────────────────────────────

@dataclass
class ServerEntry:
    ip: str = ""
    port: int = 0
    hostname: str = ""
    mapname: str = ""
    gametype: str = ""
    clients: int = 0
    maxclients: int = 0
    ping: int = 9999
    players: list[dict] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

# ── Scanner (QThread + ThreadPoolExecutor) ───────────────────

class ScanWorker(QObject):
    """Läuft in eigenem QThread und scannt Master + Server parallel.

    Alle Signale tragen die generation des Aufrufs, damit Ergebnisse eines
    abgebrochenen Scans vom Coordinator verworfen werden können.
    """

    server_updated = pyqtSignal(int, object)   # (generation, ServerEntry)
    progress = pyqtSignal(int, int, int)       # (generation, done, total)
    finished = pyqtSignal(int)                 # (generation)

    def __init__(self, master_host: str, master_port: int, generation: int,
                 parent=None):
        super().__init__(parent)
        self.master_host = master_host
        self.master_port = master_port
        self.generation = generation
        self._aborted = False

    def abort(self):
        self._aborted = True

    @pyqtSlot()
    def run(self):
        self._aborted = False
        gen = self.generation
        servers = query_master(self.master_host, self.master_port)
        if self._aborted or not servers:
            self.finished.emit(gen)
            return

        total = len(servers)
        done = 0
        import concurrent.futures

        def _query(ip, port):
            try:
                result = query_getstatus(ip, port)
            except OSError:
                return None
            if not result or self._aborted:
                return None
            try:
                info = result["info"]
                return ServerEntry(
                    ip=ip, port=port,
                    hostname=strip_colors(
                        info.get("sv_hostname") or info.get("hostname", "")),
                    mapname=info.get("mapname", ""),
                    gametype=gametype_name(
                        info.get("g_gametype") or info.get("gametype", "")),
                    clients=len(result["players"]),
                    maxclients=_int(info.get("sv_maxclients"), 0),
                    ping=info.get("ping", 9999),
                    players=result["players"],
                    raw=info,
                )
            except Exception:
                # Defekter Server darf die übrigen nicht verschlucken
                return None

        # Bewusst KEIN 'with'-Block: dessen __exit__ ruft shutdown(wait=True)
        # und würde damit auf allen ~1000 Futures blockieren (minutenlang).
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENT)
        try:
            fut_map = {pool.submit(_query, ip, port): (ip, port)
                       for ip, port in servers}
            for fut in concurrent.futures.as_completed(fut_map):
                if self._aborted:
                    break
                try:
                    se = fut.result()
                except Exception:
                    se = None
                if se:
                    # sofort ausliefern → Tabelle füllt sich live
                    self.server_updated.emit(gen, se)
                done += 1
                self.progress.emit(gen, done, total)
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

        self.finished.emit(gen)


class ScanCoordinator(QObject):
    """Startet/stoppt Scans, verwaltet den Scan-Thread."""

    server_updated = pyqtSignal(object)
    progress = pyqtSignal(int, int)
    finished = pyqtSignal()

    def __init__(self, master_host: str, master_port: int, parent=None):
        super().__init__(parent)
        self.master_host = master_host
        self.master_port = master_port
        self._thread: Optional[QThread] = None
        self._worker: Optional[ScanWorker] = None
        self._generation = 0
        # Threads, die auf shutdown noch hängen (nicht mehr referenziert,
        # aber weiterhin am Laufen – dürfen nicht zerstört werden).
        self._retiring: list[tuple[ScanWorker, QThread]] = []

    def start(self):
        self.abort()
        self._prune()
        self._generation += 1
        gen = self._generation

        thread = QThread(self)
        worker = ScanWorker(self.master_host, self.master_port, gen)
        worker.moveToThread(thread)

        thread.started.connect(worker.run)
        worker.server_updated.connect(self._on_server_updated)
        worker.progress.connect(self._on_progress)
        worker.finished.connect(self._on_worker_finished)

        self._thread = thread
        self._worker = worker
        thread.start()

    def abort(self):
        """Aktuellen Scan abbrechen und alle bisherigen Generation verwerfen."""
        self._generation += 1
        worker = self._worker
        if worker is not None:
            worker.abort()

        thread = self._thread
        if thread is None:
            return
        if thread.isRunning():
            thread.quit()
            if not thread.wait(SCAN_ABORT_TIMEOUT_MS):
                # Läuft noch (hängende getstatus-Queries bis zu 3 s).
                # Referenz behalten, sonst zerstört Python das Objekt
                # mitten im Lauf ("QThread: Destroyed while running").
                self._retiring.append((worker, thread))
                return
        self._release()

    def shutdown(self):
        """Beim Fenster-Schließen: alle Threads sauber beenden."""
        self.abort()
        for _worker, thread in self._retiring:
            thread.quit()
            thread.wait(SCAN_ABORT_TIMEOUT_MS)
        self._retiring.clear()
        self._release()

    def _release(self):
        self._thread = None
        self._worker = None

    def _prune(self):
        self._retiring = [(w, t) for (w, t) in self._retiring if t.isRunning()]

    # ── Slots mit Generations-Filter ─────────────────────────

    @pyqtSlot(int, object)
    def _on_server_updated(self, gen: int, se: ServerEntry):
        if gen == self._generation:
            self.server_updated.emit(se)

    @pyqtSlot(int, int, int)
    def _on_progress(self, gen: int, done: int, total: int):
        if gen == self._generation:
            self.progress.emit(done, total)

    @pyqtSlot(int)
    def _on_worker_finished(self, gen: int):
        # Nur der aktuelle Scan darf den Thread beenden – sonst killt das
        # verspätete Signal eines alten Workers den gerade gestarteten Scan.
        if gen != self._generation:
            return
        thread = self._thread
        if thread is not None:
            thread.quit()
        self.finished.emit()


# ── Tabelle: Serverliste ─────────────────────────────────────

SERVERS_COLS = ["", "Server", "Typ", "Map", "Spieler", "Ping", "Adresse"]

class ServerTableModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._data: list[ServerEntry] = []
        self._key: dict[str, ServerEntry] = {}
        self._favorites: set[str] = set()

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._data)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(SERVERS_COLS)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        se = self._data[index.row()]
        col = index.column()
        if col == 0:
            key = f"{se.ip}:{se.port}"
            if role == Qt.ItemDataRole.DisplayRole:
                return "★" if key in self._favorites else "☆"
            if role == Qt.ItemDataRole.TextAlignmentRole:
                return Qt.AlignmentFlag.AlignCenter
            if role == Qt.ItemDataRole.UserRole:
                return se
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            match col:
                case 1: return se.hostname or f"{se.ip}:{se.port}"
                case 2: return se.gametype
                case 3: return se.mapname
                case 4: return f"{se.clients}/{se.maxclients}"
                case 5: return se.ping if se.ping < 9999 else "-"
                case 6: return f"{se.ip}:{se.port}"
        if role == Qt.ItemDataRole.ForegroundRole and col == 5:
            p = se.ping
            if p < 50: return QBrush(QColor("#4caf50"))
            if p < 120: return QBrush(QColor("#ff9800"))
            if p < 250: return QBrush(QColor("#ff5722"))
            return QBrush(QColor("#f44336"))
        if role == Qt.ItemDataRole.UserRole:
            return se
        return None

    def flags(self, index: QModelIndex) -> Qt.ItemFlags:
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return SERVERS_COLS[section]
        return None

    def toggle_favorite(self, key: str) -> bool:
        if key in self._favorites:
            self._favorites.discard(key)
            return False
        self._favorites.add(key)
        return True

    def is_favorite(self, key: str) -> bool:
        return key in self._favorites

    def set_favorites(self, favs: set[str]):
        self._favorites = set(favs)

    def get_favorites(self) -> set[str]:
        return set(self._favorites)

    def upsert(self, se: ServerEntry):
        key = f"{se.ip}:{se.port}"
        if key in self._key:
            row = self._data.index(self._key[key])
            self._data[row] = se
            self.dataChanged.emit(self.index(row, 0), self.index(row, len(SERVERS_COLS) - 1))
        else:
            row = len(self._data)
            self.beginInsertRows(QModelIndex(), row, row)
            self._data.append(se)
            self._key[key] = se
            self.endInsertRows()
        return key

    def get(self, row: int) -> Optional[ServerEntry]:
        if 0 <= row < len(self._data):
            return self._data[row]
        return None

    def clear(self):
        self.beginResetModel()
        self._data.clear()
        self._key.clear()
        self.endResetModel()

    def __len__(self):
        return len(self._data)


class ServerFilterModel(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._text = ""
        self._hide_empty = False
        self.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

    def set_filter_text(self, text: str):
        self._text = text
        self.invalidateFilter()

    def set_hide_empty(self, hide: bool):
        self._hide_empty = hide
        self.invalidateFilter()

    def filterAcceptsRow(self, row: int, parent: QModelIndex) -> bool:
        src = self.sourceModel()
        if not src:
            return True
        idx_name = src.index(row, 1, parent)
        idx_map = src.index(row, 3, parent)
        se: ServerEntry = src.data(idx_name, Qt.ItemDataRole.UserRole)
        if not se:
            return False
        if self._hide_empty and se.clients == 0:
            return False
        if self._text:
            txt = self._text.lower()
            if txt not in se.hostname.lower() and txt not in se.mapname.lower():
                return False
        return True

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        src = self.sourceModel()
        if isinstance(src, ServerTableModel):
            se_l = src.get(left.row())
            se_r = src.get(right.row())
            if se_l and se_r:
                fav_l = src.is_favorite(f"{se_l.ip}:{se_l.port}")
                fav_r = src.is_favorite(f"{se_r.ip}:{se_r.port}")
                if fav_l != fav_r:
                    return fav_l
        return super().lessThan(left, right)


# ── Spieler-Modell ────────────────────────────────────────────

PLAYER_COLS = ["Score", "Ping", "Name"]

class PlayerTableModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._data: list[dict] = []

    def set_players(self, players: list[dict]):
        self.beginResetModel()
        self._data = list(players)
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._data)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(PLAYER_COLS)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        p = self._data[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            match index.column():
                case 0: return str(p.get("score", 0))
                case 1: return str(p.get("ping", 0))
                case 2: return p.get("name", "")
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return PLAYER_COLS[section]
        return None


class QColoredTextDelegate(QStyledItemDelegate):
    """Malt Zellen-Text mit Q3-Farbcodes (^0–^9) mehrfarbig."""

    def paint(self, painter: QPainter, option, index) -> None:
        super().paint(painter, option, QModelIndex())
        text = index.data(Qt.ItemDataRole.DisplayRole) or ""
        segments = parse_q3_colored(text)
        if not segments:
            return

        painter.save()
        painter.setFont(option.font)

        rect = option.rect.adjusted(4, 0, -4, 0)
        x = rect.x()
        baseline = rect.y() + painter.fontMetrics().ascent() + (
            rect.height() - painter.fontMetrics().height()) // 2

        selected = bool(option.state & QStyle.StateFlag.State_Selected)

        for seg_text, color in segments:
            if selected:
                painter.setPen(option.palette.color(QPalette.ColorRole.HighlightedText))
            elif color:
                painter.setPen(color)
            else:
                painter.setPen(option.palette.color(QPalette.ColorRole.Text))
            w = painter.fontMetrics().horizontalAdvance(seg_text)
            painter.drawText(x, baseline, seg_text)
            x += w

        painter.restore()


# ── Proton Auto-Detect ────────────────────────────────────────

def _detect_default_appid() -> str:
    # Bevorzugt Satisfactory (526870), sonst erster gefundener Eintrag
    for base in ("/games/SteamLibrary/steamapps/compatdata",
                 os.path.expanduser("~/.steam/steam/steamapps/compatdata")):
        if os.path.isdir(base):
            for entry in ("526870",):
                if os.path.isdir(os.path.join(base, entry)):
                    return entry
            entries = sorted(os.listdir(base))
            for entry in entries:
                if os.path.isdir(os.path.join(base, entry)) and entry.isdigit():
                    return entry
    return "526870"


# ── Einstellungen ─────────────────────────────────────────────

class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Einstellungen")
        self.setMinimumWidth(450)
        self._s = QSettings(SETTINGS_FILE, QSettings.Format.IniFormat)

        layout = QFormLayout(self)

        self.exe_path = QLineEdit(self)
        self.exe_path.setPlaceholderText("z.B. /games/alte_games/Quake 3/quake3.x86")
        self.exe_path.setText(self._s.value("exe_path", ""))
        browse_btn = QPushButton("Durchsuchen...")
        browse_btn.clicked.connect(self._browse)
        hp = QHBoxLayout()
        hp.addWidget(self.exe_path)
        hp.addWidget(browse_btn)
        layout.addRow("Q3-Pfad:", hp)

        self.exe_args = QLineEdit(self)
        self.exe_args.setPlaceholderText("+set rconPassword meinpass")
        self.exe_args.setText(self._s.value("exe_args", ""))
        layout.addRow("Zusatz-Args:", self.exe_args)

        self.proton_check = QCheckBox("Proton (Steam Play) – startet über protontricks-launch")
        self.proton_check.setChecked(self._s.value("proton", "false") == "true")
        layout.addRow(self.proton_check)

        def_appid = _detect_default_appid()
        self.proton_appid = QSpinBox(self)
        self.proton_appid.setRange(0, 9999999)
        self.proton_appid.setValue(int(self._s.value("proton_appid", def_appid)))
        layout.addRow("Steam-AppID (Prefix):", self.proton_appid)

        def _toggle_proton_fields(checked: bool):
            self.proton_appid.setEnabled(checked)
        self.proton_check.toggled.connect(_toggle_proton_fields)
        _toggle_proton_fields(self.proton_check.isChecked())

        self.rcon_pw = QLineEdit(self)
        self.rcon_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.rcon_pw.setText(self._s.value("rcon_password", ""))
        layout.addRow("RCON Passwort:", self.rcon_pw)

        self.master_host = QLineEdit(self)
        self.master_host.setText(self._s.value("master_host", MASTER_HOST))
        layout.addRow("Master-Server:", self.master_host)

        self.master_port = QSpinBox(self)
        self.master_port.setRange(1, 65535)
        self.master_port.setValue(int(self._s.value("master_port", str(MASTER_PORT))))
        layout.addRow("Master-Port:", self.master_port)

        self.refresh_interval = QSpinBox(self)
        self.refresh_interval.setRange(0, 600)
        self.refresh_interval.setSuffix(" s")
        self.refresh_interval.setSpecialValueText("Aus")
        self.refresh_interval.setValue(int(self._s.value("refresh_interval", "60")))
        layout.addRow("Auto-Refresh:", self.refresh_interval)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self._save)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Q3-Executable auswählen", os.path.expanduser("~"),
            "Binärdateien (*);;Alle (*)")
        if path:
            self.exe_path.setText(path)

    def _save(self):
        s = QSettings(SETTINGS_FILE, QSettings.Format.IniFormat)
        s.setValue("exe_path", self.exe_path.text())
        s.setValue("exe_args", self.exe_args.text())
        s.setValue("proton", "true" if self.proton_check.isChecked() else "false")
        s.setValue("proton_appid", str(self.proton_appid.value()))
        s.setValue("rcon_password", self.rcon_pw.text())
        s.setValue("master_host", self.master_host.text())
        s.setValue("master_port", str(self.master_port.value()))
        s.setValue("refresh_interval", str(self.refresh_interval.value()))
        self.accept()


# ── Hauptfenster ──────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(900, 600)
        self._s = QSettings(SETTINGS_FILE, QSettings.Format.IniFormat)
        self._restore_geometry()

        # Modelle
        self.server_model = ServerTableModel()
        self.filter_model = ServerFilterModel()
        self.filter_model.setSourceModel(self.server_model)
        self.player_model = PlayerTableModel()

        # UI aufbauen
        self._build_menu()
        self._build_toolbar()
        self._build_central()
        self._build_statusbar()

        # Coordinator (Scan-Logik)
        master = self._s.value("master_host", MASTER_HOST)
        mport = int(self._s.value("master_port", str(MASTER_PORT)))
        self._coord = ScanCoordinator(master, mport, self)
        self._coord.server_updated.connect(self._on_server_updated)
        self._coord.progress.connect(self._on_progress)
        self._coord.finished.connect(self._on_scan_done)

        # Auto-Refresh
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self.start_scan)
        self._update_refresh_timer()

        # Favoriten laden
        favs = self._s.value("favorites", [])
        if favs:
            self.server_model.set_favorites(set(favs))

        # Verbindungen
        self.sel_model = self.tableView.selectionModel()
        self.sel_model.selectionChanged.connect(self._on_selection_changed)
        self.tableView.clicked.connect(self._on_table_clicked)

        QTimer.singleShot(500, self.start_scan)

    # ── UI ────────────────────────────────────────────────────

    def _build_menu(self):
        mb = self.menuBar()
        file_menu = mb.addMenu("&Datei")
        act_quit = QAction("Beenden", self)
        act_quit.setShortcut(QKeySequence.StandardKey.Quit)
        act_quit.triggered.connect(self.close)
        file_menu.addAction(act_quit)

        set_menu = mb.addMenu("&Einstellungen")
        act_set = QAction("Einstellungen...", self)
        act_set.setShortcut(QKeySequence("Ctrl+P"))
        act_set.triggered.connect(self._open_settings)
        set_menu.addAction(act_set)

        view_menu = mb.addMenu("&Ansicht")
        self.act_hide_empty = QAction("Leere Server ausblenden", self, checkable=True)
        self.act_hide_empty.triggered.connect(self.filter_model.set_hide_empty)
        view_menu.addAction(self.act_hide_empty)

    def _build_toolbar(self):
        tb = QToolBar("Werkzeuge", self)
        s = self.style().pixelMetric(QStyle.PixelMetric.PM_SmallIconSize)
        tb.setIconSize(QSize(s, s))
        self.addToolBar(tb)

        self.btn_refresh = QPushButton("🔄 Aktualisieren")
        self.btn_refresh.clicked.connect(self.start_scan)
        tb.addWidget(self.btn_refresh)

        self.btn_connect = QPushButton("▶ Verbinden")
        self.btn_connect.setEnabled(False)
        self.btn_connect.clicked.connect(self._connect_to_server)
        tb.addWidget(self.btn_connect)

        tb.addSeparator()

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter (Name/Map)...")
        self.filter_input.setMaximumWidth(250)
        self.filter_input.textChanged.connect(self.filter_model.set_filter_text)
        tb.addWidget(self.filter_input)

        self.btn_settings = QPushButton("⚙")
        self.btn_settings.setToolTip("Einstellungen")
        self.btn_settings.clicked.connect(self._open_settings)
        tb.addWidget(self.btn_settings)

    def _build_central(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(6, 6, 6, 6)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # Server-Tabelle
        self.tableView = QTableView()
        self.tableView.setModel(self.filter_model)
        self.tableView.setSortingEnabled(True)
        self.tableView.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tableView.setAlternatingRowColors(True)
        self.tableView.setShowGrid(False)
        self.tableView.verticalHeader().hide()
        hh = self.tableView.horizontalHeader()
        hh.setStretchLastSection(True)
        hh.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hh.resizeSection(0, 28)
        hh.resizeSection(1, 240)
        hh.resizeSection(2, 60)
        hh.resizeSection(3, 120)
        hh.resizeSection(4, 70)
        hh.resizeSection(5, 60)
        self.tableView.doubleClicked.connect(self._connect_to_server)
        splitter.addWidget(self.tableView)

        # Unterer Bereich: Spieler + RCON
        bottom = QTabWidget()

        # Tab Spieler
        self.playerTable = QTableView()
        self.playerTable.setModel(self.player_model)
        self.playerTable.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.playerTable.verticalHeader().hide()
        self.playerTable.setShowGrid(False)
        self.playerTable.setItemDelegateForColumn(2, QColoredTextDelegate(self.playerTable))
        bottom.addTab(self.playerTable, "Spieler")

        # Tab RCON
        rcon_widget = QWidget()
        rcon_layout = QVBoxLayout(rcon_widget)
        rcon_layout.setContentsMargins(4, 4, 4, 4)

        self.rcon_output = QTextEdit()
        self.rcon_output.setReadOnly(True)
        self.rcon_output.setFont(QFont("monospace", 9))
        rcon_layout.addWidget(self.rcon_output)

        cmd_row = QHBoxLayout()

        self.rcon_input = QLineEdit()
        self.rcon_input.setPlaceholderText("RCON-Befehl...")
        self.rcon_input.returnPressed.connect(self._rcon_execute)
        cmd_row.addWidget(self.rcon_input)

        self.rcon_send_btn = QPushButton("Senden")
        self.rcon_send_btn.clicked.connect(self._rcon_execute)
        cmd_row.addWidget(self.rcon_send_btn)

        rcon_layout.addLayout(cmd_row)

        quick_row = QHBoxLayout()
        for label, cmd in [("status", "status"), ("Spieler", "players"),
                           ("Map", "mapname"), ("Say Hallo", "say Hallo"),
                           ("Kick", "kick {name}"), ("Shutdown", "quit")]:
            btn = QPushButton(label)
            btn.setToolTip(cmd)
            btn.clicked.connect(lambda _, c=cmd: self._rcon_quick(c))
            quick_row.addWidget(btn)
        rcon_layout.addLayout(quick_row)

        bottom.addTab(rcon_widget, "RCON")

        splitter.addWidget(bottom)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter)

    def _build_statusbar(self):
        self.sb = QStatusBar()
        self.setStatusBar(self.sb)
        self.sb_progress = QProgressBar()
        self.sb_progress.setMaximumWidth(200)
        self.sb_progress.setVisible(False)
        self.sb.addPermanentWidget(self.sb_progress)
        self.sb_label = QLabel("")
        self.sb.addPermanentWidget(self.sb_label)

    # ── Aktionen ──────────────────────────────────────────────

    def start_scan(self):
        self._coord.abort()
        self.server_model.clear()
        self.player_model.set_players([])
        self.btn_refresh.setEnabled(False)
        self.sb.showMessage("Frage Master-Server ab...")
        self.sb_progress.setValue(0)
        self.sb_progress.setVisible(True)
        self._coord.start()

    def _on_server_updated(self, se: ServerEntry):
        self.server_model.upsert(se)

    def _on_progress(self, done: int, total: int):
        self.sb_progress.setMaximum(total)
        self.sb_progress.setValue(done)
        self.sb.showMessage(f"Server abgefragt: {done}/{total}")

    def _on_scan_done(self):
        self.btn_refresh.setEnabled(True)
        self.sb_progress.setVisible(False)
        self.sb.showMessage(f"{len(self.server_model)} Server gefunden", 5000)

    def _on_selection_changed(self):
        idx = self._selected_source_index()
        if idx is not None:
            se = self.server_model.get(idx)
            if se:
                self.btn_connect.setEnabled(True)
                self.player_model.set_players(se.players)
                self.btn_connect.setToolTip(f"Verbinden mit {se.hostname}")
                return
        self.btn_connect.setEnabled(False)

    def _on_table_clicked(self, index: QModelIndex):
        if index.column() != 0:
            return
        src_idx = self.filter_model.mapToSource(index)
        se = self.server_model.get(src_idx.row())
        if not se:
            return
        key = f"{se.ip}:{se.port}"
        self.server_model.toggle_favorite(key)
        top_left = self.server_model.index(src_idx.row(), 0)
        self.server_model.dataChanged.emit(top_left, top_left)
        self._s.setValue("favorites", list(self.server_model.get_favorites()))

    def _selected_source_index(self) -> Optional[int]:
        indexes = self.tableView.selectionModel().selectedRows()
        if not indexes:
            return None
        src_idx = self.filter_model.mapToSource(indexes[0])
        return src_idx.row()

    def _connect_to_server(self):
        idx = self._selected_source_index()
        if idx is None:
            return
        se = self.server_model.get(idx)
        if not se:
            return

        exe = self._s.value("exe_path", "").strip()
        use_proton = self._s.value("proton", "false") == "true"

        if use_proton:
            # Proton braucht eine Windows-EXE – ggf. .exe ergänzen
            if exe and not exe.lower().endswith(".exe"):
                exe_candidate = exe + ".exe"
                if os.path.isfile(exe_candidate):
                    exe = exe_candidate
            appid = str(self._s.value("proton_appid", "526870"))
            if not exe or not os.path.isfile(exe):
                QMessageBox.warning(self, "Q3-EXE nicht gefunden",
                    "Q3-EXE nicht gefunden.\n"
                    "Bitte Pfad in Einstellungen korrigieren.")
                self._open_settings()
                return
            args = self._s.value("exe_args", "").strip()
            cmd = ["protontricks-launch", "--appid", appid,
                   "--no-runtime", "--no-bwrap", exe]
            if args:
                cmd.extend(args.split())
            cmd.extend(["+connect", f"{se.ip}:{se.port}"])
        else:
            if not exe:
                QMessageBox.information(self, "Kein Pfad",
                    "Bitte in Einstellungen den Pfad zur Q3-EXE angeben:\n"
                    "z.B. /games/alte_games/Quake 3/quake3.x86\n"
                    "oder ioquake3")
                self._open_settings()
                return

            if not os.path.isfile(exe):
                QMessageBox.warning(self, "Nicht gefunden",
                    f"Datei nicht gefunden:\n{exe}\n\n"
                    "Bitte Pfad in Einstellungen korrigieren.")
                self._open_settings()
                return

            args = self._s.value("exe_args", "").strip()
            cmd = [exe]
            if args:
                cmd.extend(args.split())
            cmd.extend(["+connect", f"{se.ip}:{se.port}"])
        try:
            subprocess.Popen(cmd)
        except Exception as e:
            QMessageBox.critical(self, "Fehler", f"Konnte Q3 nicht starten:\n{e}")

    def _rcon_execute(self):
        pw = self._s.value("rcon_password", "").strip()
        if not pw:
            QMessageBox.information(self, "Kein Passwort",
                "RCON-Passwort in den Einstellungen setzen.")
            self._open_settings()
            return

        cmd = self.rcon_input.text().strip()
        if not cmd:
            return
        self.rcon_input.clear()

        idx = self._selected_source_index()
        if idx is None:
            self._rcon_append("(Kein Server ausgewählt)")
            return
        se = self.server_model.get(idx)
        if not se:
            return

        self._rcon_append(f"> {cmd}")
        reply = rcon_send(se.ip, se.port, pw, cmd)
        self._rcon_append(reply)

    def _rcon_quick(self, template: str):
        idx = self._selected_source_index()
        if idx is None:
            return
        se = self.server_model.get(idx)
        if not se:
            return
        if "{name}" in template and se.players:
            name = se.players[0]["name"]
            template = template.replace("{name}", name)
        self.rcon_input.setText(template)
        self._rcon_execute()

    def _rcon_append(self, text: str):
        # Q3-Konsole haengt hinter jeder Cvar-Ausgabe ein ^7 ("S_COLOR_WHITE"),
        # damit die Konsole wieder auf Weiss zurueckspringt, z.B.
        #     "mapname" is:"q3dm6^7"
        # Das QTextEdit kann ^N nicht rendern -> Codes vor dem Anzeigen entfernen.
        # clean_output statt strip_colors: muss die Zeilenumbrueche behalten!
        self.rcon_output.append(clean_output(text))
        self.rcon_output.moveCursor(QTextCursor.MoveOperation.End)

    def _open_settings(self):
        dlg = SettingsDialog(self)
        if dlg.exec():
            self._update_refresh_timer()

    def _update_refresh_timer(self):
        interval = int(self._s.value("refresh_interval", "60"))
        if interval > 0:
            self._refresh_timer.start(interval * 1000)
        else:
            self._refresh_timer.stop()

    # ── Fenster-Geometrie ─────────────────────────────────────

    def _restore_geometry(self):
        geo = self._s.value("geometry")
        if geo:
            self.restoreGeometry(geo)
        else:
            self.resize(900, 600)

    def closeEvent(self, event):
        self._s.setValue("geometry", self.saveGeometry())
        self._s.setValue("favorites", list(self.server_model.get_favorites()))
        self._s.setValue("refresh_interval",
                         str(self._refresh_timer.interval() // 1000
                             if self._refresh_timer.isActive() else 0))
        self._coord.shutdown()
        super().closeEvent(event)


# ── Einstieg ──────────────────────────────────────────────────

def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(ORG_NAME)
    app.setStyle("Fusion")

    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
