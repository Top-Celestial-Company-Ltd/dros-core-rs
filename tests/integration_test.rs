use dros_core_rs::{types::{DrosManifest, DrosNode}, weaver::DrosWeaver};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

fn mock_manifest() -> DrosManifest {
    let mut nodes = HashMap::new();
    nodes.insert(
        "T0262".to_string(),
        DrosNode {
            id: "T0262".to_string(),
            canonical: "妙法蓮華經".to_string(),
            aliases: vec![],
            weights: HashMap::new(),
            definition: "Test".to_string(),
            synapses: vec![],
        },
    );

    DrosManifest {
        version: "v2.6".to_string(),
        metadata: HashMap::new(),
        nodes,
    }
}

#[tokio::test]
async fn test_lock_safety_and_t_coordinate() {
    let manifest = mock_manifest();
    let weaver = DrosWeaver::new(manifest);
    
    // 將 Weaver 包裝進 Tokio 異步的 Arc<RwLock> 中
    // 這將強制編譯器檢查 DrosWeaver 是否嚴格符合 Send + Sync 特徵
    let async_weaver = Arc::new(RwLock::new(weaver));

    // 模擬並發調度
    let weaver_clone1 = async_weaver.clone();
    let handle1 = tokio::spawn(async move {
        // 取得讀取鎖
        let guard = weaver_clone1.read().await;
        
        let result = guard.weave("我們查詢 T0262 直連測試");
        let mut t_score = 0.0;
        for m in result {
            if m.node_id == "T0262" {
                if let Some(score) = m.score {
                    t_score = score;
                }
            }
        }
        assert_eq!(t_score, 40.0, "T-Coordinate 應賦予 40.0 溢價分");
    });

    let weaver_clone2 = async_weaver.clone();
    let handle2 = tokio::spawn(async move {
        let guard = weaver_clone2.read().await;
        let node = guard.get_node("T0262");
        assert!(node.is_some(), "必須找到 T0262");
    });

    handle1.await.unwrap();
    handle2.await.unwrap();
}
