#!/usr/bin/env python3
"""SeeP GUI MCP Server — desktop automation via pyautogui.

Provides mouse, keyboard, screenshot, and screen-inspection tools so SeeP can
drive the desktop. Cross-platform (Windows/macOS/Linux) through pyautogui.

Safety notes:
- pyautogui's fail-safe is ON: slam the mouse into a screen corner to abort.
- All actions go through SeeP's blast-radius scoring (see seep-safety), so
  clicks/typing are MEDIUM and require confirmation by default.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from seep_mcp_base import McpServer, McpError

# pyautogui is imported lazily so the server can start and report a clear,
# actionable error instead of crashing if the dependency / display is missing.
_pg = None
_pg_error = None


def _gui():
    global _pg, _pg_error
    if _pg is not None:
        return _pg
    if _pg_error is not None:
        raise McpError(-32001, _pg_error)
    try:
        import pyautogui  # type: ignore
        pyautogui.FAILSAFE = True
        pyautogui.PAUSE = 0.05
        _pg = pyautogui
        return _pg
    except Exception as e:  # ImportError, or no display (headless Linux)
        _pg_error = (
            f"pyautogui unavailable: {e}. "
            "Install with: pip install pyautogui pillow"
            + ("" if os.name == "nt" else " (and on Linux: python3-tk, scrot/xdotool, a running display)")
        )
        raise McpError(-32001, _pg_error)


class GuiServer(McpServer):
    SERVER_NAME = "seep-gui"

    async def setup(self):
        self.register_tool("gui_screen_size", "Get the primary screen resolution (width, height)",
            {"type": "object", "properties": {}}, self.gui_screen_size)

        self.register_tool("gui_mouse_position", "Get the current mouse cursor position",
            {"type": "object", "properties": {}}, self.gui_mouse_position)

        self.register_tool("gui_move", "Move the mouse to absolute (x, y)",
            {"type": "object", "properties": {
                "x": {"type": "integer"}, "y": {"type": "integer"},
                "duration": {"type": "number", "default": 0.2}},
             "required": ["x", "y"]}, self.gui_move)

        self.register_tool("gui_click", "Click the mouse (optionally at x, y)",
            {"type": "object", "properties": {
                "x": {"type": "integer"}, "y": {"type": "integer"},
                "button": {"type": "string", "enum": ["left", "right", "middle"], "default": "left"},
                "clicks": {"type": "integer", "default": 1},
                "interval": {"type": "number", "default": 0.0}}},
            self.gui_click)

        self.register_tool("gui_double_click", "Double-click (optionally at x, y)",
            {"type": "object", "properties": {
                "x": {"type": "integer"}, "y": {"type": "integer"},
                "button": {"type": "string", "enum": ["left", "right", "middle"], "default": "left"}}},
            self.gui_double_click)

        self.register_tool("gui_drag", "Drag the mouse from current position to (x, y)",
            {"type": "object", "properties": {
                "x": {"type": "integer"}, "y": {"type": "integer"},
                "duration": {"type": "number", "default": 0.4},
                "button": {"type": "string", "enum": ["left", "right", "middle"], "default": "left"}},
             "required": ["x", "y"]}, self.gui_drag)

        self.register_tool("gui_scroll", "Scroll vertically; positive = up, negative = down",
            {"type": "object", "properties": {
                "amount": {"type": "integer"},
                "x": {"type": "integer"}, "y": {"type": "integer"}},
             "required": ["amount"]}, self.gui_scroll)

        self.register_tool("gui_type", "Type a string of text at the current focus",
            {"type": "object", "properties": {
                "text": {"type": "string"},
                "interval": {"type": "number", "default": 0.0}},
             "required": ["text"]}, self.gui_type)

        self.register_tool("gui_press", "Press one or more keys (e.g. 'enter', 'esc', 'tab')",
            {"type": "object", "properties": {
                "keys": {"type": "array", "items": {"type": "string"}},
                "presses": {"type": "integer", "default": 1}},
             "required": ["keys"]}, self.gui_press)

        self.register_tool("gui_hotkey", "Press a key combination (e.g. ['ctrl','c'])",
            {"type": "object", "properties": {
                "keys": {"type": "array", "items": {"type": "string"}}},
             "required": ["keys"]}, self.gui_hotkey)

        self.register_tool("gui_screenshot", "Capture the screen (or a region) to a PNG file",
            {"type": "object", "properties": {
                "path": {"type": "string", "description": "Output PNG path"},
                "region": {"type": "array", "items": {"type": "integer"},
                           "description": "[left, top, width, height] (optional)"}},
             "required": ["path"]}, self.gui_screenshot)

        self.register_tool("gui_locate", "Locate an image on screen, return its center (x, y) or null",
            {"type": "object", "properties": {
                "image": {"type": "string", "description": "Path to the needle PNG"},
                "confidence": {"type": "number", "default": 0.9}},
             "required": ["image"]}, self.gui_locate)

        self.register_tool("gui_alert", "Show a desktop alert/message box",
            {"type": "object", "properties": {
                "text": {"type": "string"}, "title": {"type": "string", "default": "SeeP"}},
             "required": ["text"]}, self.gui_alert)

    # ── Handlers ─────────────────────────────────────────────────────────────
    async def gui_screen_size(self, args):
        w, h = _gui().size()
        return json.dumps({"width": int(w), "height": int(h)})

    async def gui_mouse_position(self, args):
        x, y = _gui().position()
        return json.dumps({"x": int(x), "y": int(y)})

    async def gui_move(self, args):
        _gui().moveTo(args["x"], args["y"], duration=float(args.get("duration", 0.2)))
        return f"Moved to ({args['x']}, {args['y']})"

    async def gui_click(self, args):
        pg = _gui()
        kwargs = {
            "button": args.get("button", "left"),
            "clicks": int(args.get("clicks", 1)),
            "interval": float(args.get("interval", 0.0)),
        }
        if "x" in args and "y" in args:
            kwargs["x"] = args["x"]
            kwargs["y"] = args["y"]
        pg.click(**kwargs)
        loc = f" at ({args['x']}, {args['y']})" if "x" in args and "y" in args else ""
        return f"Clicked {kwargs['button']}{loc}"

    async def gui_double_click(self, args):
        pg = _gui()
        kwargs = {"button": args.get("button", "left")}
        if "x" in args and "y" in args:
            kwargs["x"] = args["x"]; kwargs["y"] = args["y"]
        pg.doubleClick(**kwargs)
        return "Double-clicked"

    async def gui_drag(self, args):
        _gui().dragTo(args["x"], args["y"],
                      duration=float(args.get("duration", 0.4)),
                      button=args.get("button", "left"))
        return f"Dragged to ({args['x']}, {args['y']})"

    async def gui_scroll(self, args):
        pg = _gui()
        if "x" in args and "y" in args:
            pg.scroll(int(args["amount"]), x=args["x"], y=args["y"])
        else:
            pg.scroll(int(args["amount"]))
        return f"Scrolled {args['amount']}"

    async def gui_type(self, args):
        _gui().typewrite(args["text"], interval=float(args.get("interval", 0.0)))
        return f"Typed {len(args['text'])} characters"

    async def gui_press(self, args):
        keys = args["keys"]
        if not isinstance(keys, list):
            keys = [keys]
        _gui().press(keys, presses=int(args.get("presses", 1)))
        return f"Pressed: {', '.join(keys)}"

    async def gui_hotkey(self, args):
        keys = args["keys"]
        if not isinstance(keys, list) or not keys:
            raise McpError(-32602, "keys must be a non-empty array")
        _gui().hotkey(*keys)
        return f"Hotkey: {'+'.join(keys)}"

    async def gui_screenshot(self, args):
        pg = _gui()
        path = args["path"]
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        region = args.get("region")
        if region and len(region) == 4:
            img = pg.screenshot(region=tuple(region))
        else:
            img = pg.screenshot()
        img.save(path)
        return f"Screenshot saved to {path} ({img.width}x{img.height})"

    async def gui_locate(self, args):
        pg = _gui()
        try:
            box = pg.locateCenterOnScreen(args["image"], confidence=float(args.get("confidence", 0.9)))
        except TypeError:
            # confidence requires opencv; retry without it.
            box = pg.locateCenterOnScreen(args["image"])
        if box is None:
            return json.dumps({"found": False})
        return json.dumps({"found": True, "x": int(box[0]), "y": int(box[1])})

    async def gui_alert(self, args):
        _gui().alert(text=args["text"], title=args.get("title", "SeeP"))
        return "Alert dismissed"


if __name__ == "__main__":
    GuiServer.main()
