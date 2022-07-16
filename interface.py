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
                [sg.Checkbox('ip database',True,key="ipdb")],
                [sg.Checkbox('auto block',True,key="autoblock")]
            ]
        
        block_layout = [
            [
            sg.Text("IP:"),
            sg.Input(size=(20,20),key="blockip"),
            sg.Button("Block IP",expand_x=True,expand_y=True,key="block"),
            sg.Button("Unblock IP",expand_x=True,expand_y=True,key="unblock"),
            ]
        ]
        
        column1_layout = [
            [
            sg.Frame("E-mail settings:", email_layout,expand_y=True,expand_x=True),
            sg.Frame("Packets settings:", packets_layout,expand_y=True,expand_x=True),
            ],
            [sg.Frame("IP blocking:",block_layout,expand_y=True,expand_x=True)]
        ]
        
        buttons_layout = [
            [sg.Button( "Start scan", expand_x=True,expand_y=True,key='scan')],
            [sg.Button( "Quit", expand_x=True,expand_y=True,key='quit')],
        ]
        
        main_layout = [
                [sg.Multiline( expand_x=True,size=(0,20), key="output", autoscroll=True,disabled=True,reroute_stdout=True,auto_refresh=True)],
                [
                    sg.Column(column1_layout),
                    sg.Frame("Actions", check_layout,expand_y=True,expand_x=True),
                    sg.Column(buttons_layout,expand_x=True,expand_y=True)
                ],
                [sg.ProgressBar(100, orientation='h', expand_x=True,bar_color=("green","grey"),k='pbar')]
            ]

        title = 'malicious traffic scanner'
        self.window = sg.Window( title, main_layout, ttk_theme='clam', use_ttk_buttons=True)
        self.open = True 

    def progress(self,value):
        self.window['pbar'].update(value)
        self.update()

    def update( self):
        event, values = self.window.read(timeout=100)
        
        if event == sg.WIN_CLOSED or event == "quit":
            self.open = False 
            self.window.close()

        return event, values 

def main():
    ui = Interface()
    while ui.open:
        ui.update()

if __name__ == "__main__":
    main()
