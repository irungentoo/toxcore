#include <wx\wx.h>
#include "home\Home.h"

class Tox : public wxApp
{
  public:
    virtual bool OnInit();
};



bool Tox::OnInit()
{
    Home *home = new Home(wxT("Tox"));
    home->Show(true);

    return true;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE prevInstance, LPWSTR lpCmdLine, int nShowCmd)
{
    char *buf;

    buf = new char[wcslen(lpCmdLine) + 1];

    wcstombs(buf, lpCmdLine, wcslen(lpCmdLine) +1);

    wxApp::SetInstance( new Tox());
	
    wxEntry(hInstance, prevInstance, buf, nShowCmd);

    wxEntryCleanup();
}