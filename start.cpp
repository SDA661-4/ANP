#include "start.h"
#include "ui_start.h"
#include "mainwindow.h"
#include "sniffer.h"

MainWindow* openWind;
Sniffer* openSniff;

Start::Start(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::Start)
{
    ui->setupUi(this);
    openWind=new MainWindow();
    openSniff=new Sniffer();
    connect(ui->actioncalculator,SIGNAL(triggered()),this,SLOT(opeN()));
    connect(ui->Sniff,SIGNAL(triggered()),this,SLOT(opSniffer()));
    ui->actionexit,SIGNAL(close()),this;

}
void Start::opeN()
{
openWind->show();
}

void Start::opSniffer()
{
 openSniff->show();
}

Start::~Start()
{
    delete ui;
}
