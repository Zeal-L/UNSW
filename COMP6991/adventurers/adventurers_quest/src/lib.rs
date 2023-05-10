//! # Adventurers Quest
//!
//! `adventurers_quest` is a library for managing quests for termgame.
//!
//! More information can be found in the separate modules.


pub mod quest;
pub mod quest_combine;
pub mod quest_single;


#[cfg(test)]
mod tests {
    use crate::quest::{QuestEvent, BlockType, QuestStatus, example_quest};

    #[test]
    fn test_q1() {
        let q = example_quest("q1".to_string());
        assert!(q.is_some());
        let mut q = q.unwrap();
        assert_eq!(q.is_complete(), QuestStatus::Ongoing);

        for _ in 0..5 {
            q.register_event(QuestEvent::WalkedOnBlock(BlockType::Sand));
        }
        assert_eq!(q.is_complete(), QuestStatus::Complete);

        q.reset();
        assert_eq!(q.is_complete(), QuestStatus::Ongoing);
    }

    #[test]
    fn test_q2() {
        let q = example_quest("q2".to_string());
        assert!(q.is_some());
        let mut q = q.unwrap();
        assert_eq!(q.is_complete(), QuestStatus::Ongoing);

        for _ in 0..3 {
            q.register_event(QuestEvent::CollectItem(BlockType::Object('y')));
        }
        for _ in 0..5 {
            q.register_event(QuestEvent::CollectItem(BlockType::Object('x')));
        }
        assert_eq!(q.is_complete(), QuestStatus::Ongoing);

        for _ in 0..5 {
            q.register_event(QuestEvent::CollectItem(BlockType::Object('x')));
        }
        for _ in 0..3 {
            q.register_event(QuestEvent::CollectItem(BlockType::Object('y')));
        }
        assert_eq!(q.is_complete(), QuestStatus::Complete);

        q.reset();
        assert_eq!(q.is_complete(), QuestStatus::Ongoing);
    }

    #[test]
    fn test_q3() {
        let q = example_quest("q3".to_string());
        assert!(q.is_some());
        let mut q = q.unwrap();
        assert_eq!(q.is_complete(), QuestStatus::Ongoing);

        for _ in 0..5 {
            q.register_event(QuestEvent::WalkedOnBlock(BlockType::Sand));
        }
        q.register_event(QuestEvent::CollectItem(BlockType::Object('x')));

        assert_eq!(q.is_complete(), QuestStatus::Ongoing);

        for _ in 0..3 {
            for _ in 0..9 {
                q.register_event(QuestEvent::WalkedOnBlock(BlockType::Water));
            }
        }
        assert_eq!(q.is_complete(), QuestStatus::Complete);

        q.reset();
        assert_eq!(q.is_complete(), QuestStatus::Ongoing);
    }
}
