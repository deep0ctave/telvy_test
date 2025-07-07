import React, { useState, useEffect } from "react";
import { getFullQuiz, updateFullQuiz } from "../../../services/api";
import { toast } from "react-toastify";
import { Plus, GripVertical, Trash2, ChevronDown, ChevronUp } from "lucide-react";
import {
  DndContext,
  closestCenter,
  PointerSensor,
  useSensor,
  useSensors,
} from "@dnd-kit/core";
import {
  SortableContext,
  useSortable,
  arrayMove,
  verticalListSortingStrategy,
} from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";

const QuestionItem = ({ question, idx, readonly, onChange, onDelete, collapsed, toggle }) => {
  const { attributes, listeners, setNodeRef, transform, transition } = useSortable({ id: question.tempId });
  const style = { transform: CSS.Transform.toString(transform), transition };

  return (
    <div ref={setNodeRef} style={style} className="bg-base-100 border rounded-lg p-4 shadow mb-3">
      <div className="flex justify-between items-center">
        <div className="flex items-center gap-2">
          <GripVertical {...attributes} {...listeners} className="cursor-grab"/>
          <div>
            <p className="font-semibold">Q{idx + 1}: {question.question_text || "Untitled question"}</p>
            <p className="text-sm text-base-content/50">{question.question_type}</p>
          </div>
        </div>
        <div className="flex gap-2">
          {!readonly && <button onClick={onDelete} className="btn btn-sm btn-error btn-outline"><Trash2 /></button>}
          <button onClick={toggle} className="btn btn-sm btn-ghost">
            {collapsed ? <ChevronDown /> : <ChevronUp />}
          </button>
        </div>
      </div>

      {!collapsed && (
        <div className="mt-4 space-y-3">
          <label className="input">
            <span className="label">Text</span>
            <input
              value={question.question_text}
              disabled={readonly}
              onChange={e => onChange(idx, "question_text", e.target.value)}
            />
          </label>

          <label className="input">
            <span className="label">Type</span>
            <select
              value={question.question_type}
              disabled={readonly}
              onChange={e => onChange(idx, "question_type", e.target.value)}
              className="select select-bordered"
            >
              <option value="mcq">MCQ</option>
              <option value="true_false">True/False</option>
              <option value="type_in">Type-in</option>
            </select>
          </label>

          {question.question_type === "mcq" && (
            <div className="space-y-2">
              {[...Array(4)].map((_, oi) => (
                <div key={oi} className="flex items-center gap-2">
                  <input
                    className="input input-bordered flex-grow"
                    placeholder={`Option ${oi + 1}`}
                    value={question.options[oi]?.option_text || ""}
                    disabled={readonly}
                    onChange={e => onChange(idx, `opt_text_${oi}`, e.target.value)}
                  />
                  <input
                    type="radio"
                    name={`correct-${question.tempId}`}
                    disabled={readonly}
                    checked={question.options[oi]?.is_correct || false}
                    onChange={() => onChange(idx, "correct_index", oi)}
                  />
                </div>
              ))}
            </div>
          )}

          {question.question_type === "true_false" && (
            <div className="space-y-2">
              {["True", "False"].map((label, oi) => (
                <div key={oi} className="flex items-center gap-2">
                  <input
                    type="radio"
                    name={`tf-${question.tempId}`}
                    disabled={readonly}
                    checked={question.options?.[oi]?.is_correct}
                    onChange={() => onChange(idx, "correct_index", oi)}
                  />
                  <span>{label}</span>
                </div>
              ))}
            </div>
          )}

          {question.question_type === "type_in" && (
            <label className="input">
              <span className="label">Answer</span>
              <input
                value={question.accepted_answers[0] || ""}
                disabled={readonly}
                onChange={e => onChange(idx, "accepted_answers_0", e.target.value)}
              />
            </label>
          )}
        </div>
      )}
    </div>
  );
};

export default function EditQuizModal({ quizId, onClose, onSave, readonly = false }) {
  const [quiz, setQuiz] = useState(null);
  const [loading, setLoading] = useState(true);
  const sensors = useSensors(useSensor(PointerSensor));

  useEffect(() => {
    const loadQuiz = async () => {
      try {
        const res = await getFullQuiz(quizId);
        const fetched = res.data;
        setQuiz({
          ...fetched,
          questions: fetched.questions.map((q, i) => ({
            ...q,
            tempId: `q-${q.id}-${i}`,
            collapsed: false,
          }))
        });
      } catch (err) {
        toast.error("Failed to load quiz");
        onClose();
      } finally { setLoading(false) }
    };
    loadQuiz();
  }, [quizId]);

  const handleChange = (idx, field, value) => {
  setQuiz(q => {
    const qs = [...q.questions];
    const item = { ...qs[idx] };

    // Ensure options array exists if needed
    if ((item.question_type === "mcq" || item.question_type === "true_false") && !item.options) {
      item.options = [];
    }

    // Handle changing question type
    if (field === "question_type") {
      item.question_type = value;
      if (value === "mcq") {
        item.options = Array(4).fill(null).map(() => ({ option_text: "", is_correct: false }));
        item.accepted_answers = [];
      } else if (value === "true_false") {
        item.options = [
          { option_text: "True", is_correct: true },
          { option_text: "False", is_correct: false },
        ];
        item.accepted_answers = [];
      } else if (value === "type_in") {
        item.accepted_answers = [""];
        item.options = [];
      }
    }

    // Handle other changes
    else if (field.startsWith("opt_text_")) {
      const oi = +field.split("_")[2];
      item.options[oi] = item.options[oi] || { option_text: "", is_correct: false };
      item.options[oi].option_text = value;
    } else if (field === "correct_index") {
      if (item.options) {
        item.options = item.options.map((o, i) => ({ ...o, is_correct: i === value }));
      }
    } else if (field.startsWith("accepted_answers_")) {
      const ai = +field.split("_")[2];
      item.accepted_answers = [...(item.accepted_answers || [])];
      item.accepted_answers[ai] = value;
    } else {
      item[field] = value;
    }

    qs[idx] = item;
    return { ...q, questions: qs };
  });

  console.log(`Changed Q${idx + 1} field ${field}:`, value);
};

  const toggleCollapse = idx => setQuiz(q => {
    const qs = [...q.questions];
    qs[idx].collapsed = !qs[idx].collapsed;
    return { ...q, questions: qs };
  });

  const deleteQuestion = idx => setQuiz(q => ({
    ...q,
    questions: q.questions.filter((_,i) => i !== idx)
  }));

  const handleDragEnd = event => {
    const { active, over } = event;
    if (active.id !== over?.id) {
      setQuiz(q => ({
        ...q,
        questions: arrayMove(
          q.questions,
          q.questions.findIndex(x => x.tempId === active.id),
          q.questions.findIndex(x => x.tempId === over.id)
        )
      }));
    }
  };

  const handleSave = async () => {
    console.log("[SAVE QUIZ]", quiz);
    try {
      const payload = {
        title: quiz.title,
        description: quiz.description,
        image_url: quiz.image_url,
        quiz_type: quiz.quiz_type,
        time_limit: quiz.time_limit,
        tags: quiz.tags,
        questions: quiz.questions.map(q => ({
          id: q.id,
          question_text: q.question_text,
          question_image: q.question_image,
          question_type: q.question_type,
          tags: q.tags,
          options: q.options,
          accepted_answers: q.accepted_answers
        }))
      };
      await updateFullQuiz(quizId, payload);
      toast.success("Quiz updated!");
      onSave({ ...quiz });
      onClose();
    } catch (err) {
      console.error("[SAVE ERROR]", err);
      toast.error(err?.response?.data?.message || "Failed to save");
    }
  };

  if (loading) {
    return <div className="modal modal-open"><div className="modal-box">Loading…</div></div>;
  }
  if (!quiz) return null;

  return (
    <div className="modal modal-open">
      <div className="modal-box max-w-4xl max-h-[90vh] overflow-auto">
        <h2 className="text-2xl font-bold mb-4">Edit Quiz</h2>

        <label className="input w-full">
          <span className="label">Title</span>
          <input
            value={quiz.title}
            disabled={readonly}
            onChange={e => setQuiz(q => ({ ...q, title: e.target.value }))}
          />
        </label>
        <label className="input w-full mt-2">
          <span className="label">Description</span>
          <textarea
            className="textarea textarea-bordered w-full"
            rows={2}
            value={quiz.description || ""}
            disabled={readonly}
            onChange={e => setQuiz(q => ({ ...q, description: e.target.value }))}
          />
        </label>
        <label className="input w-full mt-2">
          <span className="label">Tags (comma-separated)</span>
          <input
            value={quiz.tags.join(", ")}
            disabled={readonly}
            onChange={e => setQuiz(q => ({
              ...q,
              tags: e.target.value.split(",").map(t => t.trim()).filter(Boolean),
            }))}
          />
        </label>

        <div className="grid grid-cols-2 gap-4 mt-4">
          <label className="input">
            <span className="label">Type</span>
            <select
              className="select select-bordered"
              value={quiz.quiz_type}
              disabled={readonly}
              onChange={e => setQuiz(q => ({ ...q, quiz_type: e.target.value }))}
            >
              <option value="anytime">Anytime</option>
              <option value="scheduled">Scheduled</option>
            </select>
          </label>
          <label className="input">
            <span className="label">Time Limit (sec)</span>
            <input
              type="number"
              className="input input-bordered"
              value={quiz.time_limit}
              disabled={readonly}
              onChange={e => setQuiz(q => ({ ...q, time_limit: +e.target.value }))}
            />
          </label>
        </div>

        <div className="mt-6">
          <div className="flex justify-between items-center mb-2">
            <h3 className="text-lg font-semibold">Questions ({quiz.questions.length})</h3>
            <button className="btn btn-sm btn-outline" disabled={readonly} onClick={() => setQuiz(q => ({
              ...q,
              questions: [
                ...q.questions,
                { tempId: `q-new-${Date.now()}`, question_text: "", question_type: "mcq", options: [], accepted_answers: [], collapsed: false }
              ]
            }))}>
              <Plus /> Add Question
            </button>
          </div>

          <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
            <SortableContext items={quiz.questions.map(q => q.tempId)} strategy={verticalListSortingStrategy}>
              {quiz.questions.map((q, idx) => (
                <QuestionItem
                  key={q.tempId}
                  question={q}
                  idx={idx}
                  readonly={readonly}
                  onDelete={() => deleteQuestion(idx)}
                  collapsed={q.collapsed}
                  toggle={() => toggleCollapse(idx)}
                  onChange={handleChange}
                />
              ))}
            </SortableContext>
          </DndContext>
        </div>

        <div className="modal-action justify-end mt-6">
          <button className="btn" onClick={onClose}>Cancel</button>
          {!readonly && <button className="btn btn-primary" onClick={handleSave}>Save Quiz</button>}
        </div>
      </div>
    </div>
  );
}
