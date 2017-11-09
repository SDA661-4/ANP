#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <math.h>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

float z=0;
float q=0;
float s=0;
int c=0;
int OP=0;



MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_Null_clicked()
{
    z=z*10;
    ui->Screen->setText(QString::number(z));
}

void MainWindow::on_One_clicked()
{
    z=z*10+1;
    ui->Screen->setText(QString::number(z));
}

void MainWindow::on_Two_clicked()
{
    z=z*10+2;
    ui->Screen->setText(QString::number(z));
}

void MainWindow::on_Three_clicked()
{
    z=z*10+3;
    ui->Screen->setText(QString::number(z));
}

void MainWindow::on_Four_clicked()
{
    z=z*10+4;
    ui->Screen->setText(QString::number(z));
}

void MainWindow::on_Five_clicked()
{
    z=z*10+5;
    ui->Screen->setText(QString::number(z));
}

void MainWindow::on_Six_clicked()
{
    z=z*10+6;
    ui->Screen->setText(QString::number(z));
}

void MainWindow::on_Seven_clicked()
{
    z=z*10+7;
    ui->Screen->setText(QString::number(z));
}

void MainWindow::on_Eight_clicked()
{
    z=z*10+8;
    ui->Screen->setText(QString::number(z));
}

void MainWindow::on_Nine_clicked()
{
    z=z*10+9;
    ui->Screen->setText(QString::number(z));
}

void MainWindow::on_C_clicked()
{
    z=0;
    q=0;
    s=0;
    OP=0;
    ui->Screen->setText(QString::number(z));
    ui->ScreenOP->setText(" ");
    ui->ScreenPR->setText(" ");
}

void MainWindow::on_Sign_clicked()
{
    z=(-1)*z;
    ui->Screen->setText(QString::number(z));
}

void MainWindow::on_Procent_clicked()
{
    q=z;
    z=0;
    OP=1;
    ui->ScreenPR->setText(QString::number(q));
    ui->ScreenOP->setText("%");
    ui->Screen->setText(QString::number(z));
}

void MainWindow::on_Eq_clicked()
{
   switch (OP)
   {
   case 1: s=z*q/100; OP=0; break;
   case 2: s=z+q; OP=0; break;
   case 3: s=q-z; OP=0;break;
   case 4: s=z*q; OP=0; break;
   case 5: s=q/z; OP=0; break;
   case 6: s=pow(q,z); OP=0; break;
   case 7: s=sqrt(q); OP=0; break;
   }
   ui->Screen->setText(QString::number(s));
   ui->ScreenPR->setText(QString::number(q));
   ui->ScreenOP->setText("=");
   z=s;
   q=0;
}

void MainWindow::on_Delete_clicked()
{
    c=z*10;
    if ((c%10)!=0)
     z=c/10;
    else
     z=c/100;
    ui->Screen->setText(QString::number(z));
}

void MainWindow::on_Sum_clicked()
{
    if (OP!=0)
            switch (OP)
            {
            case 1: q=z*q/100; OP=0; break;
            case 2: q=z+q; OP=0; break;
            case 3: q=q-z; OP=0;break;
            case 4: q=z*q; OP=0; break;
            case 5: q=q/z; OP=0; break;
            case 6: q=pow(q,z); OP=0; break;
            case 7: q=sqrt(q); OP=0; break;
            }
    else q=z;
    OP=2;
    z=0;
    ui->ScreenPR->setText(QString::number(q));
    ui->ScreenOP->setText("+");
    ui->Screen->setText(QString::number(z));
}

void MainWindow::on_Minus_clicked()
{
    if (OP!=0)
            switch (OP)
            {
            case 1: q=z*q/100; OP=0; break;
            case 2: q=z+q; OP=0; break;
            case 3: q=q-z; OP=0;break;
            case 4: q=z*q; OP=0; break;
            case 5: q=q/z; OP=0; break;
            case 6: q=pow(q,z); OP=0; break;
            case 7: q=sqrt(q); OP=0; break;
            }
    else q=z;
    OP=3;
    z=0;
    ui->ScreenPR->setText(QString::number(q));
    ui->ScreenOP->setText("-");
    ui->Screen->setText(QString::number(z));
}

void MainWindow::on_Umnoj_clicked()
{
    if (OP!=0)
            switch (OP)
            {
            case 1: q=z*q/100; OP=0; break;
            case 2: q=z+q; OP=0; break;
            case 3: q=q-z; OP=0;break;
            case 4: q=z*q; OP=0; break;
            case 5: q=q/z; OP=0; break;
            case 6: q=pow(q,z); OP=0; break;
            case 7: q=sqrt(q); OP=0; break;
            }
    else q=z;
    OP=4;
    z=0;
    ui->ScreenPR->setText(QString::number(q));
    ui->ScreenOP->setText("*");
    ui->Screen->setText(QString::number(z));
}

void MainWindow::on_Delenie_clicked()
{
    if (OP!=0)
            switch (OP)
            {
            case 1: q=z*q/100; OP=0; break;
            case 2: q=z+q; OP=0; break;
            case 3: q=q-z; OP=0;break;
            case 4: q=z*q; OP=0; break;
            case 5: q=q/z; OP=0; break;
            case 6: q=pow(q,z); OP=0; break;
            case 7: q=sqrt(q); OP=0; break;
            }
    else q=z;
    OP=5;
    z=0;
    ui->ScreenPR->setText(QString::number(q));
    ui->ScreenOP->setText("/");
    ui->Screen->setText(QString::number(z));
}

void MainWindow::on_Stepen_clicked()
{
    if (OP!=0)
            switch (OP)
            {
            case 1: q=z*q/100; OP=0; break;
            case 2: q=z+q; OP=0; break;
            case 3: q=q-z; OP=0;break;
            case 4: q=z*q; OP=0; break;
            case 5: q=q/z; OP=0; break;
            case 6: q=pow(q,z); OP=0; break;
            case 7: q=sqrt(q); OP=0; break;
            }
    else q=z;
    OP=6;
    z=0;
    ui->ScreenPR->setText(QString::number(q));
    ui->ScreenOP->setText("^");
    ui->Screen->setText(QString::number(z));
}

void MainWindow::on_Root_clicked()
{
    if (OP!=0)
            switch (OP)
            {
            case 1: q=z*q/100; OP=0; break;
            case 2: q=z+q; OP=0; break;
            case 3: q=q-z; OP=0;break;
            case 4: q=z*q; OP=0; break;
            case 5: q=q/z; OP=0; break;
            case 6: q=pow(q,z); OP=0; break;
            case 7: q=sqrt(q); OP=0; break;
            }
    else q=z;
    OP=7;
    z=0;
    ui->ScreenPR->setText(QString::number(q));
    ui->ScreenOP->setText("√");
    ui->Screen->setText(QString::number(z));
}
