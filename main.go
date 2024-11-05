package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image/color"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

const apiKey = "13ca33527e18735619f7aa0c140117bacd3d6743930c273ab0dc74065f5dd4df"

type VirusTotalResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious int `json:"malicious"`
			} `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
}

func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("Антивирус")

	// Загрузка изображения
	img := canvas.NewImageFromFile("icon.jpg")
	img.FillMode = canvas.ImageFillOriginal

	scanButton := widget.NewButton("Запустить антивирус", func() {
		resultsBox := container.NewVBox(widget.NewLabel("Сканирование..."))
		scrollContainer := container.NewVScroll(resultsBox)
		scrollContainer.SetMinSize(fyne.NewSize(800, 400)) // Установите размеры контейнера

		myWindow.SetContent(scrollContainer)

		go func() {
			processes, err := getActiveProcesses()
			if err != nil || len(processes) == 0 {
				resultsBox.Add(widget.NewLabel("Процессы не найдены"))
				return
			}

			foundMalicious := false
			var scanResults []fyne.CanvasObject
			for _, process := range processes {
				var maliciousLabel string
				if isMalicious(process) {
					maliciousLabel = "Вирусный"
					foundMalicious = true
					showAlert(process) // Показать окно с предупреждением о вирусе
					break              // Прерываем цикл, если найден вирусный процесс
				} else {
					maliciousLabel = "Безопасный"
				}
				processLabel := widget.NewLabel(fmt.Sprintf("%s: %s", process, maliciousLabel))
				processLabel.TextStyle = fyne.TextStyle{Bold: true}
				processLabel.Text = fmt.Sprintf("%s: %s", process, maliciousLabel) // Устанавливаем белый цвет текста
				resultsBox.Add(processLabel)                                       // Добавляем процесс в результаты сканирования
				resultsBox.Add(widget.NewSeparator())                              // Добавляем разделитель
				scanResults = append(scanResults, processLabel, widget.NewSeparator())

				// Прокрутка к последнему добавленному элементу
				scrollContainer.ScrollToBottom()
			}

			if !foundMalicious {
				// Показать зеленый экран, если вирусы не найдены
				greenBackground := canvas.NewRectangle(color.RGBA{0, 255, 0, 255}) // Зеленый фон
				greenBackground.SetMinSize(fyne.NewSize(800, 600))

				successLabel := widget.NewLabelWithStyle(
					"Проверка процессов прошла успешно. Вирусов обнаружено: 0",
					fyne.TextAlignCenter,
					fyne.TextStyle{Bold: true},
				)
				successLabel.TextStyle = fyne.TextStyle{Bold: true} // Устанавливаем белый цвет текста

				resultScroll := container.NewVScroll(container.NewVBox(scanResults...))
				resultScroll.SetMinSize(fyne.NewSize(800, 600)) // Устанавливаем размер на весь экран

				myWindow.SetContent(container.NewMax(
					greenBackground,
					container.NewVBox(
						container.NewCenter(successLabel),
						resultScroll, // Используем контейнер с прокруткой и установленным размером
					),
				))
			}
		}()
	})

	myWindow.SetContent(container.NewVBox(
		img,        // Добавляем изображение в интерфейс
		scanButton, // Используем переменную scanButton в содержимом окна
	))

	myWindow.ShowAndRun()
}

func getFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func isMalicious(process string) bool {
	hash, err := getFileHash(process)
	if err != nil {
		return false
	}

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("x-apikey", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		time.Sleep(2 * time.Second)
		return isMalicious(process)
	}

	if resp.StatusCode != http.StatusOK {
		return false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	var vtResponse VirusTotalResponse
	err = json.Unmarshal(body, &vtResponse)
	if err != nil {
		return false
	}

	return vtResponse.Data.Attributes.LastAnalysisStats.Malicious > 0
}

func removeVirus(filePath string) error {
	directory := filepath.Dir(filePath)

	// Завершение всех процессов, находящихся в указанной директории
	killCmd := fmt.Sprintf("Get-Process | Where-Object { $_.Path -like '%s\\*' } | Stop-Process -Force", directory)
	cmd := exec.Command("powershell", "-Command", killCmd)
	cmd.CombinedOutput()

	// Удаление автозапуска из реестра
	regDeleteCmd := fmt.Sprintf("Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' | ForEach-Object { if ($_.Value -like '*%s*') { Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name $_.Name -Force } }", directory)
	cmd = exec.Command("powershell", "-Command", regDeleteCmd)
	cmd.CombinedOutput()

	// Добавляем паузу для завершения процессов и удаления автозапуска
	time.Sleep(3 * time.Second)

	// Удаление файла вируса с правами администратора
	deleteCmd := fmt.Sprintf("del /F /Q \"%s\"", filePath)
	deleteScript := fmt.Sprintf("Start-Process cmd.exe -ArgumentList '/C %s' -Verb RunAs", deleteCmd)
	cmd = exec.Command("powershell", "-Command", deleteScript)
	cmd.CombinedOutput()

	return nil
}

func showAlert(process string) {
	alertWindow := fyne.CurrentApp().NewWindow("Вирус обнаружен!")
	alertWindow.Resize(fyne.NewSize(400, 200))

	redBackground := canvas.NewRectangle(color.RGBA{255, 0, 0, 255}) // Красный фон
	redBackground.SetMinSize(fyne.NewSize(400, 200))

	content := widget.NewLabelWithStyle(fmt.Sprintf("Обнаружен вирусный процесс: %s", process), fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	deleteButton := widget.NewButton("Удалить вирус", func() {
		err := removeVirus(process)
		alertWindow.Hide() // Скрыть текущее окно
		if err != nil {
			showRemovalResult("Не удалось удалить вирус", false) // Показать окно с результатом удаления
		} else {
			showRemovalResult("Вирус успешно удален", true) // Показать окно с результатом удаления
		}
	})

	alertWindow.SetContent(container.NewMax(
		redBackground,
		container.NewVBox(
			content,
			deleteButton,
		),
	))

	alertWindow.Show()
}

func showRemovalResult(message string, success bool) {
	resultWindow := fyne.CurrentApp().NewWindow("Результат удаления")
	resultWindow.Resize(fyne.NewSize(400, 200))

	var bgColor color.RGBA
	if success {
		bgColor = color.RGBA{0, 255, 0, 255} // Зеленый фон для успеха
	} else {
		bgColor = color.RGBA{255, 0, 0, 255} // Красный фон для неудачи
	}
	background := canvas.NewRectangle(bgColor)
	background.SetMinSize(fyne.NewSize(400, 200))

	content := widget.NewLabelWithStyle(message, fyne.TextAlignCenter, fyne.TextStyle{Bold: true})

	resultWindow.SetContent(container.NewMax(
		background,
		container.NewCenter(content),
	))

	resultWindow.Show()
}

func getActiveProcesses() ([]string, error) {
	cmd := exec.Command("powershell", "-Command", "Get-Process | Select-Object -ExpandProperty Path")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	processes := strings.Split(string(output), "\n")
	var validProcesses []string
	for _, process := range processes {
		if process != "" {
			validProcesses = append(validProcesses, strings.TrimSpace(process))
		}
	}
	return validProcesses, nil
}
