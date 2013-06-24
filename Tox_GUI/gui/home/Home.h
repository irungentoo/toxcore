#include <wx\wx.h>

class Home : public wxFrame
{
public:
    Home(const wxString& title);

	void AddNew(wxCommandEvent& event);

	wxListBox *netlogList;
};

const int ID_LISTBOX = 1;