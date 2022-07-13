import PySimpleGUI as sg

class Interface:
    def __init__( self, email="", count=256, size=128):
        sg.theme('Topanga')

        email_layout = [
                [sg.Text( 'e-mail:',size=(8,1)),sg.Input(key='email', size=(20,1),default_text=email)],
                [sg.Text( 'password:',size=(8,1)),sg.Input(key='passw', size=(20,1),password_char="*")]
            ]

        packets_layout = [
                [sg.Text( 'min size:',size=(8,1)),sg.Input(key='size',size=(10,1),default_text=size)],
                [sg.Text( 'count:',size=(8,1)),sg.Input(key='count',size=(10,1),default_text=count)]
            ]

        check_layout = [
                [sg.Checkbox('DNS check',True,key="dns")],
                [sg.Checkbox('snort',True,key="snort")],
                [sg.Checkbox('ip database',True,key="ipdb")]
            ]

        main_layout = [
            [
                sg.Output( size=(95,16), key="output")],
                [
                    sg.Frame("E-mail settings:", email_layout, size=(200,110)),
                    sg.Frame("Packets settings:", packets_layout, size=(180,110)),
                    sg.Frame("Actions", check_layout, size=(180,110)),
                    sg.Button( "Start scan", size=(4,2),key='scan'),
                ],
            [
                sg.ProgressBar(100, orientation='h', s=(68,20), k='pbar')]
            ]

        title = 'malicious traffic scanner'
        self.window = sg.Window( title, main_layout, ttk_theme='clam', use_ttk_buttons=True)
        self.open = True 

    def progress(self,value):
        self.window['pbar'].update(value)
        self.update()

    def error(msg):
        sg.popup_error(msg)

    def update( self):
        event, values = self.window.read(timeout=100)
        
        if event == sg.WIN_CLOSED:
            self.open = False 
            self.window.close()
            return

        return event, values 

if __name__ == "__main__":
    ui = Interface()
    while ui.open:
        ui.update()
