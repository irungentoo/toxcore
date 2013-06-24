#include <wx\textdlg.h>
#include "Home.h"

Home::Home(const wxString& title)
	: wxFrame(NULL, wxID_ANY, title, wxDefaultPosition, wxSize(750, 450))
{
	wxPanel * panel = new wxPanel(this, -1);

	wxBoxSizer *hbox = new wxBoxSizer(wxHORIZONTAL);

	netlogList = new wxListBox(panel, ID_LISTBOX, 
		wxPoint(-1, -1), wxSize(-1, -1)); 

	hbox->Add(netlogList, 3, wxEXPAND | wxALL, 20);

	panel->SetSizer(hbox);

	Centre();

	netlogList->Append("Testing..."); 
}

void Home::AddNew(wxCommandEvent& event) 
{
  wxString str = wxGetTextFromUser(wxT("Add new item"));
  if (str.Len() > 0)
      netlogList->Append(str); 
}