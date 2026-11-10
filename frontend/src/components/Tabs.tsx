import React, { useId, useRef } from "react";

export interface TabDefinition {
  id: string;
  label: string;
  content: React.ReactNode;
}

interface TabsProps {
  label: string;
  items: TabDefinition[];
  activeId: string;
  onChange: (id: string) => void;
}

export const Tabs: React.FC<TabsProps> = ({ label, items, activeId, onChange }) => {
  const baseId = useId();
  const btnRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const activeIndex = Math.max(
    0,
    items.findIndex((item) => item.id === activeId)
  );
  const currentItem = items[activeIndex];

  const focusAndSelect = (nextIndex: number) => {
    const wrapped = (nextIndex + items.length) % items.length;
    onChange(items[wrapped].id);
    btnRefs.current[wrapped]?.focus();
  };

  const handleKeyDown = (idx: number, e: React.KeyboardEvent<HTMLButtonElement>) => {
    if (e.key === "ArrowRight") {
      e.preventDefault();
      focusAndSelect(idx + 1);
    } else if (e.key === "ArrowLeft") {
      e.preventDefault();
      focusAndSelect(idx - 1);
    } else if (e.key === "Home") {
      e.preventDefault();
      focusAndSelect(0);
    } else if (e.key === "End") {
      e.preventDefault();
      focusAndSelect(items.length - 1);
    }
  };

  if (!currentItem) return null;

  return (
    <div>
      <div className="tablist" role="tablist" aria-label={label}>
        {items.map((item, idx) => {
          const isSelected = idx === activeIndex;
          return (
            <button
              key={item.id}
              ref={(el) => {
                btnRefs.current[idx] = el;
              }}
              id={`${baseId}-tab-${item.id}`}
              type="button"
              role="tab"
              className="tab-btn"
              aria-selected={isSelected}
              tabIndex={isSelected ? 0 : -1}
              onClick={() => onChange(item.id)}
              onKeyDown={(e) => handleKeyDown(idx, e)}
            >
              {item.label}
            </button>
          );
        })}
      </div>

      <div role="tabpanel" aria-labelledby={`${baseId}-tab-${currentItem.id}`}>
        <div className="tabpanel-frame">{currentItem.content}</div>
      </div>
    </div>
  );
};
