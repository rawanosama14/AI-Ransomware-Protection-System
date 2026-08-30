from __future__ import annotations

import logging
import queue
from pathlib import Path
from typing import Callable, Optional

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from detector import RansomwareDetector, DetectionResult

EventCallback = Callable[[str, str, Optional[str], DetectionResult], None]

class MonitorHandler(FileSystemEventHandler):
    def __init__(self, detector: RansomwareDetector, callback: EventCallback) -> None:
        super().__init__()
        self.detector = detector
        self.callback = callback

    def _handle(self, event_type: str, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        path = getattr(event, "src_path", "")
        dest = getattr(event, "dest_path", None)
        result = self.detector.add_event(event_type, path, dest)
        logging.info("%s | %s | %s | risk=%s score=%s", event_type, path, dest or "", result.risk_level, result.score)
        self.callback(event_type, path, dest, result)

    def on_created(self, event: FileSystemEvent) -> None:
        self._handle("created", event)

    def on_modified(self, event: FileSystemEvent) -> None:
        self._handle("modified", event)

    def on_moved(self, event: FileSystemEvent) -> None:
        self._handle("moved", event)

    def on_deleted(self, event: FileSystemEvent) -> None:
        self._handle("deleted", event)

class FolderMonitor:
    def __init__(self, folder: str, callback: EventCallback, detector: Optional[RansomwareDetector] = None) -> None:
        self.folder = str(Path(folder).expanduser().resolve())
        self.detector = detector or RansomwareDetector()
        self.callback = callback
        self.observer: Optional[Observer] = None

    def start(self) -> None:
        if self.observer is not None:
            return
        handler = MonitorHandler(self.detector, self.callback)
        observer = Observer()
        observer.schedule(handler, self.folder, recursive=True)
        observer.start()
        self.observer = observer
        logging.info("Started monitoring %s", self.folder)

    def stop(self) -> None:
        if self.observer is None:
            return
        self.observer.stop()
        self.observer.join(timeout=3)
        self.observer = None
        logging.info("Stopped monitoring %s", self.folder)
