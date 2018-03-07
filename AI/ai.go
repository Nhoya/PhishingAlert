package main

import (
	"fmt"
	"github.com/sjwhitworth/golearn/base"
	"github.com/sjwhitworth/golearn/evaluation"
	"github.com/sjwhitworth/golearn/knn"
)

func main() {
	rawData, err := base.ParseCSVToInstances("phishing.csv", false)
	if err != nil {
		panic(err)
	}

	fmt.Println(rawData)
	cls := knn.NewKnnClassifier("euclidean", "linear", 2)

	// Split data
	trainData, testData := base.InstancesTrainTestSplit(rawData, 0.8)
	cls.Fit(trainData)

	predictions, err := cls.Predict(testData)
	if err != nil {
		panic(err)
	}

	// Prints precision/recall metrics
	confusionMat, err := evaluation.GetConfusionMatrix(testData, predictions)
	if err != nil {
		panic(fmt.Sprintf("Unable to get confusion matrix: %s", err.Error()))
	}
	fmt.Println(evaluation.GetSummary(confusionMat))
}
