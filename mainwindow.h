#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:

    void on_Null_clicked();

    void on_One_clicked();

    void on_Two_clicked();

    void on_Three_clicked();

    void on_Four_clicked();

    void on_Five_clicked();

    void on_Six_clicked();

    void on_Seven_clicked();

    void on_Eight_clicked();

    void on_Nine_clicked();

    void on_C_clicked();

    void on_Sign_clicked();

    void on_Procent_clicked();

    void on_Eq_clicked();

    void on_Delete_clicked();

    void on_Sum_clicked();

    void on_Minus_clicked();

    void on_Umnoj_clicked();

    void on_Delenie_clicked();

    void on_Stepen_clicked();

    void on_Root_clicked();

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
