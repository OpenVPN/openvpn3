//
//  console.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

// console utilities for Windows

#ifndef OPENVPN_WIN_CONSOLE_H
#define OPENVPN_WIN_CONSOLE_H

#include <windows.h>
#include <string>
#include <boost/noncopyable.hpp>
#include <openvpn/win/handle.hpp>

namespace openvpn {
  namespace Win {
    namespace Console {

      class Input : boost::noncopyable
      {
      public:
	Input()
	  : std_input(Handle::undefined()),
	    console_mode_save(0)
	{
	  // disable control-C
	  SetConsoleCtrlHandler(NULL, TRUE);

	  HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
	  DWORD mode = 0;
	  if (Handle::defined(in) && GetConsoleMode(in, &mode))
	    {
	      // running on a console
	      const DWORD newmode = mode
		& ~(ENABLE_WINDOW_INPUT
		    | ENABLE_PROCESSED_INPUT
		    | ENABLE_LINE_INPUT
		    | ENABLE_ECHO_INPUT 
		    | ENABLE_MOUSE_INPUT);

	      if (newmode == mode || SetConsoleMode(in, newmode))
		{
		  std_input = in;
		  console_mode_save = mode;
		}
	    }
	}

	~Input()
	{
	  if (Handle::defined(std_input))
	    SetConsoleMode(std_input, console_mode_save);
	}

	bool available()
	{
	  if (Handle::defined(std_input))
	    {
	      DWORD n;
	      if (GetNumberOfConsoleInputEvents(std_input, &n))
		return n > 0;
	    }
	  return false;
	}

	unsigned int get()
	{
	  if (Handle::defined(std_input))
	    {
	      INPUT_RECORD ir;
	      do {
		DWORD n;
		if (!available())
		  return 0;
		if (!ReadConsoleInput(std_input, &ir, 1, &n))
		  return 0;
	      } while (ir.EventType != KEY_EVENT || ir.Event.KeyEvent.bKeyDown != TRUE);
	      return keyboard_ir_to_key(&ir);
	    }
	  else
	    return 0;
	}

      private:
	unsigned int keyboard_ir_to_key(INPUT_RECORD *ir)
	{
	  if (ir->Event.KeyEvent.uChar.AsciiChar == 0)
	    return ir->Event.KeyEvent.wVirtualScanCode;

	  if ((ir->Event.KeyEvent.dwControlKeyState
	       & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED))
	      && (ir->Event.KeyEvent.wVirtualKeyCode != 18))
	    return ir->Event.KeyEvent.wVirtualScanCode * 256;

	  return ir->Event.KeyEvent.uChar.AsciiChar;
	}

	HANDLE std_input;
	DWORD console_mode_save;
      };

      class Title : boost::noncopyable
      {
      public:
	Title(const std::string& new_title)
	  : old_title_defined(false)
	{
	  char title[256];
	  if (GetConsoleTitle(title, sizeof(title)))
	    {
	      old_title = title;
	      old_title_defined = true;
	    }
	  SetConsoleTitle(new_title.c_str());
	}

	~Title()
	{
	  if (old_title_defined)
	    SetConsoleTitle(old_title.c_str());
	}
      private:
	bool old_title_defined;
	std::string old_title;
      };
    }
  }
}

#endif
