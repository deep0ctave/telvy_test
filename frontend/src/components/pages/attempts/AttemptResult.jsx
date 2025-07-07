// File: components/pages/Student/AttemptResult.jsx
import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { CheckCircle, XCircle, AlertCircle } from "lucide-react";

const mockAttemptData = {
  quiz_title: "Mock Quiz",
  total_score: 3,
  max_score: 5,
  time_taken_seconds: 380,
  questions: [
    {
      id: 1,
      question_text: "What is 2 + 2?",
      question_type: "mcq",
      options: ["2", "3", "4", "5"],
      correct_option: "4",
      selected_option: "4",
    },
    {
      id: 2,
      question_text: "The sky is blue. (True/False)",
      question_type: "true_false",
      options: ["True", "False"],
      correct_option: "True",
      selected_option: "False",
    },
    {
      id: 3,
      question_text: "Capital of India?",
      question_type: "type_in",
      correct_answer: "New Delhi",
      user_answer: "Delhi",
    },
  ],
};

const AttemptResult = () => {
  const { attemptId } = useParams();
  const [attempt, setAttempt] = useState(null);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);

  useEffect(() => {
    // Simulate fetch
    setAttempt(mockAttemptData);
  }, [attemptId]);

  const currentQuestion = attempt?.questions[currentQuestionIndex];

  const formatTime = (seconds) => {
    const m = Math.floor(seconds / 60)
      .toString()
      .padStart(2, "0");
    const s = (seconds % 60).toString().padStart(2, "0");
    return `${m}:${s}`;
  };

  const renderQuestionResult = (q) => {
    if (q.question_type === "mcq" || q.question_type === "true_false") {
      return (
        <div className="space-y-2">
          {q.options.map((opt, i) => {
            const isCorrect = opt === q.correct_option;
            const isSelected = opt === q.selected_option;
            const isWrong = isSelected && !isCorrect;

            return (
              <div
                key={i}
                className={`p-2 rounded border flex items-center gap-2 ${
                  isCorrect
                    ? "bg-green-100 border-green-400"
                    : isWrong
                    ? "bg-red-100 border-red-400"
                    : "border-base-300"
                }`}
              >
                <input
                  type="radio"
                  className="radio"
                  disabled
                  checked={isSelected}
                />
                <span>{opt}</span>
                {isCorrect && <CheckCircle size={16} className="text-green-600" />}
                {isWrong && <XCircle size={16} className="text-red-600" />}
              </div>
            );
          })}
        </div>
      );
    }

    if (q.question_type === "type_in") {
      return (
        <div className="space-y-2">
          <div
            className={`p-2 rounded border ${
              q.user_answer?.toLowerCase().trim() ===
              q.correct_answer?.toLowerCase().trim()
                ? "bg-green-100 border-green-400"
                : "bg-red-100 border-red-400"
            }`}
          >
            <strong>Your Answer:</strong> {q.user_answer || <em>Not answered</em>}
          </div>
          <div className="p-2 rounded border border-base-300 bg-base-200">
            <strong>Correct Answer:</strong> {q.correct_answer}
          </div>
        </div>
      );
    }

    return <div>Unsupported question type.</div>;
  };

  if (!attempt) return <div className="p-6">Loading results...</div>;

  return (
    <div className="p-6">
      <div className="mb-6 space-y-1">
        <h2 className="text-xl font-bold">{attempt.quiz_title}</h2>
        <p>
          Score:{" "}
          <span className="font-medium">
            {attempt.total_score}/{attempt.max_score}
          </span>{" "}
          • Time: <span className="font-mono">{formatTime(attempt.time_taken_seconds)}</span>
        </p>
      </div>

      <div className="flex flex-col lg:flex-row gap-6">
        {/* Left: Question + Result */}
        <div className="flex-1 space-y-4">
          <div className="card bg-base-200 border border-base-300 shadow">
            <div className="card-body space-y-4">
              <h2 className="card-title">
                Question {currentQuestionIndex + 1} of {attempt.questions.length}
              </h2>
              <p className="text-lg">{currentQuestion?.question_text}</p>
              {renderQuestionResult(currentQuestion)}
            </div>
          </div>

          <div className="flex justify-between">
            <button
              className="btn"
              disabled={currentQuestionIndex === 0}
              onClick={() => setCurrentQuestionIndex((i) => i - 1)}
            >
              Previous
            </button>
            <button
              className="btn"
              disabled={currentQuestionIndex === attempt.questions.length - 1}
              onClick={() => setCurrentQuestionIndex((i) => i + 1)}
            >
              Next
            </button>
          </div>
        </div>

        {/* Right: Navigator */}
        <div className="w-full lg:w-64 shrink-0 bg-base-100 border border-base-300 rounded-box p-4 shadow">
          <h3 className="font-semibold text-center mb-2">Navigate</h3>
          <div className="grid grid-cols-5 gap-2 justify-center">
            {attempt.questions.map((q, i) => {
              const correct =
                q.question_type === "type_in"
                  ? q.user_answer?.toLowerCase().trim() ===
                    q.correct_answer?.toLowerCase().trim()
                  : q.selected_option === q.correct_option;
              return (
                <button
                  key={q.id}
                  className={`btn btn-xs ${
                    i === currentQuestionIndex
                      ? "btn-primary"
                      : correct
                      ? "btn-success"
                      : "btn-error"
                  }`}
                  onClick={() => setCurrentQuestionIndex(i)}
                >
                  {i + 1}
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

export default AttemptResult;
